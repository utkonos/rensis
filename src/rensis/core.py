"""Library for reverse engineering the Nullsoft Scriptable Install System (NSIS)."""
import hashlib
import importlib.resources
import io
import lzma
import re
import struct
import zlib

import nsisunbz2.core
import pefile
import yara


class NSISFile:
    """Parses one NSIS installer."""

    def __init__(self, data):
        if not isinstance(data, bytes):
            raise TypeError('Input must be bytes')
        self.data = data
        self.f = io.BytesIO(data)

        stubid = importlib.resources.files('rensis.data').joinpath('stubid.yar').read_text()
        rules = yara.compile(source=stubid)
        matches = rules.match(data=data)
        if not any(matches):
            raise LookupError('Unknown StubID')
        for m in rules.match(data=data):
            if 'zlib' in m.rule:
                self.compression_type = 'zlib'
            elif 'lzma' in m.rule:
                self.compression_type = 'lzma'
            elif 'bzip2' in m.rule:
                self.compression_type = 'bzip2'
            else:
                raise LookupError('Unknown compression')

            if 'solid' in m.rule:
                self.solid = True
            else:
                self.solid = False

        self.matches = matches

        self.sha256 = None

        self.pe = None

        self.data_offset = None
        self.misaligned = None
        self.dislocated = None

        self.invalid_fh_flags_content = None
        self.force_crc = None
        self.no_crc = None
        self.silent = None
        self.uninstall = None
        self.impossible_crc_flags = None

        self.script_size = None

        self.archive_size = None

        self.decompressed_size = None

        self.compressed = None
        self.header_size = None

        self.script_bin = None
        self.script_bin_sha256 = None
        self.script_size_mismatch = None

        self.error = None
        self.compressed_data = None

    def _get_bytes(self, n, name):
        """Read n bytes from the file stream."""
        nextbytes = self.f.read(n)

        if not len(nextbytes):
            raise RuntimeError(f'Data stream read error: {name} not found')
        if len(nextbytes) != n:
            raise RuntimeError(f'Data stream read error: unexpected length of {name}')

        return nextbytes

    def _sha256(self):
        """Calculate the SHA256 hash of the input file."""
        sha256 = hashlib.sha256(self.data).hexdigest()

        self.sha256 = sha256

    def _pefile(self):
        """Run the pefile parser and store the resulting object."""
        pe = pefile.PE(data=self.data)

        self.pe = pe

    def _nsis_data(self):
        """Find the offset of the NSIS data overlay."""
        magic = re.compile(b'\xef\xbe\xad\xdeNullsoftInst')
        match = re.search(magic, self.data)
        if not match:
            raise RuntimeError(f'Invalid NSIS: magic not found: {self.sha256}')

        offset = match.start() - 4
        misaligned = True if offset % 0x200 else False

        last_section = self.pe.sections[-1]
        overlay = last_section.PointerToRawData + last_section.SizeOfRawData
        dislocated = True if overlay != offset else False

        self.f.seek(offset)

        self.data_offset = offset
        self.misaligned = misaligned
        self.dislocated = dislocated

    def _fh_flags(self):
        """Get the file header flags."""
        nextbytes = self._get_bytes(4, 'fh_flags')
        fh_flags, = struct.unpack('I', nextbytes)

        invalid_fh_flags_bits = True if fh_flags & 0xFFFFFFF0 else False
        if invalid_fh_flags_bits:
            invalid_fh_flags_content = fh_flags >> 4
            fh_flags &= 0xf

        force_crc = True if fh_flags & 0x8 else False
        no_crc = True if fh_flags & 0x4 else False
        silent = True if fh_flags & 0x2 else False
        uninstall = True if fh_flags & 0x1 else False
        impossible_crc_flags = True if force_crc and no_crc else False

        _ = self._get_bytes(16, 'magic')

        if invalid_fh_flags_bits:
            self.invalid_fh_flags_content = invalid_fh_flags_content
        self.force_crc = force_crc
        self.no_crc = no_crc
        self.silent = silent
        self.uninstall = uninstall
        self.impossible_crc_flags = impossible_crc_flags

    def _script_size(self):
        """Get the size of the compiled NSIS install script."""
        nextbytes = self._get_bytes(4, 'script_size')
        script_size, = struct.unpack('I', nextbytes)

        self.script_size = script_size

    def _archive_size(self):
        """Get the total size of the NSIS data."""
        nextbytes = self._get_bytes(4, 'archive_size')
        archive_size, = struct.unpack('I', nextbytes)

        if self.solid:
            archive_size -= 28
            if not self.no_crc:
                archive_size -= 4

        self.archive_size = archive_size

    def _header_info(self):
        """Get the information about the NSIS header."""
        nextbytes = self._get_bytes(4, 'header_info')
        header_info, = struct.unpack('I', nextbytes)

        compressed = True if header_info & 0x80000000 else False
        header_size = header_info & 0x7fffffff

        self.compressed = compressed
        self.header_size = header_size

    def _zlib_decompress(self):
        """Decompress the compressed stream using zlib."""
        if self.solid:
            nextbytes = self._get_bytes(self.archive_size, 'compressed_solid_data_size')
        else:
            nextbytes = self._get_bytes(self.header_size, 'compressed_header_size')
        try:
            decompressed = zlib.decompress(nextbytes, wbits=-zlib.MAX_WBITS)
        except zlib.error as e:
            self.error = e
            self.compressed_data = nextbytes
            return

        if self.solid:
            d = io.BytesIO(decompressed)
            nextbytes = d.read(4)
            script_size, = struct.unpack('I', nextbytes)
            script_bin = d.read(script_size)
        else:
            script_bin = decompressed
        script_bin_sha256 = hashlib.sha256(script_bin).hexdigest()
        script_size_mismatch = True if len(script_bin) != self.script_size else False

        self.script_bin = script_bin
        self.script_bin_sha256 = script_bin_sha256
        self.script_size_mismatch = script_size_mismatch

    def _lzma_decompress(self):
        """Decompress the compressed stream using LZMA2."""
        if self.solid:
            remaining_compressed_data = self.archive_size
        else:
            remaining_compressed_data = self.header_size
        properties_len = 1
        nextbytes = self._get_bytes(properties_len, 'lzma_properties')
        properties, = struct.unpack('B', nextbytes)
        remaining_compressed_data -= properties_len

        dictionary_size_len = 4
        nextbytes = self._get_bytes(dictionary_size_len, 'lzma_dictionary_size')
        dictionary_size = nextbytes
        remaining_compressed_data -= dictionary_size_len

        uncompressed_size = b'\xff' * 8  # 0xffffffffffffffff

        nextbytes = self._get_bytes(remaining_compressed_data, 'lzma_compressed_data')
        compressed_data = nextbytes

        lzma_input = bytes([properties]) + dictionary_size + uncompressed_size + compressed_data
        decompressed = lzma.decompress(lzma_input)

        if self.solid:
            d = io.BytesIO(decompressed)
            nextbytes = d.read(4)
            script_size, = struct.unpack('I', nextbytes)
            script_bin = d.read(script_size)
        else:
            script_bin = decompressed
        script_bin_sha256 = hashlib.sha256(script_bin).hexdigest()
        script_size_mismatch = True if len(script_bin) != self.script_size else False

        self.script_bin = script_bin
        self.script_bin_sha256 = script_bin_sha256
        self.script_size_mismatch = script_size_mismatch

    def _bzip2_decompress(self):
        """Decompress the compressed stream using Bzip2."""
        if self.solid:
            nextbytes = self._get_bytes(self.archive_size, 'compressed_solid_data_size')
            bzd = nsisunbz2.core.Bz2Decompress(nextbytes)
            decompressed = bzd.decompress(self.script_size)
            d = io.BytesIO(decompressed)
            nextbytes = d.read(4)
            script_size, = struct.unpack('I', nextbytes)
            script_bin = d.read(script_size)
        else:
            nextbytes = self._get_bytes(self.header_size, 'compressed_header_size')
            bzd = nsisunbz2.core.Bz2Decompress(nextbytes, self.script_size)
            script_bin = bzd.decompress()

        script_bin_sha256 = hashlib.sha256(script_bin).hexdigest()
        script_size_mismatch = True if len(script_bin) != self.script_size else False

        self.script_bin = script_bin
        self.script_bin_sha256 = script_bin_sha256
        self.script_size_mismatch = script_size_mismatch

    def _copy_script(self):
        """Copy an uncompressed NSIS install script."""
        script_bin = self._get_bytes(self.header_size, 'uncompressed_header_size')
        script_bin_sha256 = hashlib.sha256(script_bin).hexdigest()
        script_size_mismatch = True if len(script_bin) != self.script_size else False

        self.script_bin = script_bin
        self.script_bin_sha256 = script_bin_sha256
        self.script_size_mismatch = script_size_mismatch

    def run(self):
        """Execute the steps needed to decompress the compiled NSIS install script."""
        self._sha256()
        self._pefile()
        self._nsis_data()
        self._fh_flags()
        self._script_size()
        self._archive_size()
        if not self.solid:
            self._header_info()
        if self.compressed or self.solid:
            match self.compression_type:
                case 'zlib':
                    self._zlib_decompress()
                case 'lzma':
                    self._lzma_decompress()
                case 'bzip2':
                    self._bzip2_decompress()
        else:
            self._copy_script()
