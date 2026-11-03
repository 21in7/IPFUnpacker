"""Native reader and CLI regressions using only small, generated IPF archives.

Set IPF_TEST_SANITIZE=1 to compile the driver and CLI with ASan and UBSan.
"""
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import zlib


ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = b'data.ipf'
FILENAME = b'payload.lua'
PAYLOAD = b'payload'
FOOTER = struct.Struct('<HIHIIII')
ENTRY = struct.Struct('<HIIIIH')
DRIVER = r'''
#include "ipf_unpack/ipf.h"
#include "dbg/dbg.h"
#include <stdio.h>
#include <string.h>
typedef struct { size_t calls; size_t fail_at; bool valid; } State;
static bool visit(uint8_t *data, size_t size, char *archive, char *filename, void *opaque) {
    State *state = opaque;
    state->calls++;
    state->valid = state->valid && size == 7 && memcmp(data, "payload", 7) == 0
        && strcmp(archive, "data.ipf") == 0 && strcmp(filename, "payload.lua") == 0;
    return state->valid && state->calls != state->fail_at;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    dbgSetOutput(stderr);
    FILE *file = fopen(argv[1], "rb");
    if (!file || fseek(file, 0, SEEK_END)) return 2;
    long length = ftell(file);
    if (length < 0 || fseek(file, 0, SEEK_SET)) return 2;
    size_t size = (size_t) length;
    uint8_t *data = malloc(size ? size : 1);
    if (!data || fread(data, 1, size, file) != size) return 2;
    fclose(file);
    State state = {0, (size_t) strtoul(argv[2], NULL, 10), true};
    bool ok = ipf_read(data, size, visit, &state);
    printf("RESULT %d %zu %d\n", ok, state.calls, state.valid);
    free(data);
    return 0;
}
'''


def name_entry(archive=b'old.ipf', filename=b'directory/old.lua'):
    return struct.pack('<HH', len(archive), len(filename)) + archive + filename


def archive(count=1, names=b'', unk=0, payload=PAYLOAD):
    record = ENTRY.pack(len(FILENAME), 0, len(payload), len(PAYLOAD),
                        0, len(ARCHIVE)) + ARCHIVE + FILENAME
    table = record * count
    footer = FOOTER.pack(count & 0xffff, len(payload), unk,
                         len(payload) + len(table), 0x06054b50, 1, 2)
    return payload + table + names + footer


def replace_footer(data, **changes):
    fields = ['count', 'table', 'unk', 'end', 'magic', 'base', 'revision']
    values = dict(zip(fields, FOOTER.unpack(data[-FOOTER.size:])))
    values.update(changes)
    return data[:-FOOTER.size] + FOOTER.pack(*(values[key] for key in fields))


class IPFReadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ipf-reader-test-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.directory = Path(cls.temp.name)
        driver = cls.directory / 'driver.c'
        driver.write_text(DRIVER, encoding='utf-8')
        cls.reader = cls.directory / 'reader'
        cls.cli = cls.directory / 'ipf_unpack'
        flags = ['-std=gnu99', '-D_GNU_SOURCE', '-g', '-O1',
                 '-I' + str(ROOT / 'src'), '-I' + str(ROOT / 'src/common')]
        if os.environ.get('IPF_TEST_SANITIZE') == '1':
            flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                      '-fno-omit-frame-pointer', '-fno-pie', '-no-pie']
        common = ROOT / 'src/common'
        subprocess.run(['gcc'] + flags + [str(driver),
                       str(ROOT / 'src/ipf_unpack/ipf.c'),
                       str(common / 'dbg/dbg.c'), '-o', str(cls.reader)], check=True)
        sources = [ROOT / 'src/ipf_unpack' / name
                   for name in ('ipf.c', 'ipf_unpack.c', 'ies.c')]
        sources += [common / name / (name + '.c')
                    for name in ('dbg', 'zlib', 'crc32', 'fs', 'md5')]
        subprocess.run(['gcc'] + flags + [str(p) for p in sources]
                       + ['-lz', '-o', str(cls.cli)], check=True)

    def read_archive(self, data, expected=True, calls=1, fail_at=0):
        path = self.directory / 'input.ipf'
        path.write_bytes(data)
        result = subprocess.run([str(self.reader), str(path), str(fail_at)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        rows = [line for line in result.stdout.splitlines() if line.startswith('RESULT ')]
        self.assertEqual(rows, ['RESULT {} {} 1'.format(int(expected), calls)],
                         result.stdout + result.stderr)
        self.assertEqual(path.read_bytes(), data)

    def reject(self, data):
        self.read_archive(data, expected=False, calls=0)

    def test_legacy_empty_interval_preserves_unknown_field(self):
        for count in (0, 1, 3):
            for unk in (0, 1115, 65535):
                with self.subTest(count=count, unk=unk):
                    self.read_archive(archive(count=count, unk=unk), calls=count)

    def test_name_lists_are_validated_without_callbacks(self):
        for entries in ([name_entry()],
                        [name_entry(), name_entry(b'other.ipf', b'dir/')],
                        [name_entry(b'a' * 257, b'b' * 513)],
                        [name_entry(b'', b'')]):
            for count in (0, 2):
                with self.subTest(entries=len(entries), count=count):
                    self.read_archive(archive(count, b''.join(entries), len(entries)),
                                      calls=count)

    def test_name_count_mismatch(self):
        for unk in (0, 1, 3, 65535):
            with self.subTest(unk=unk):
                self.reject(archive(names=name_entry() * 2, unk=unk))

    def test_truncated_name_length_header(self):
        for length in (1, 2, 3):
            with self.subTest(length=length):
                self.reject(archive(names=name_entry() + b'\0' * length, unk=2))

    def test_name_lengths_cannot_cross_footer(self):
        for lengths in ((65535, 1), (1, 65535), (65535, 65535), (1, 2)):
            with self.subTest(lengths=lengths):
                self.reject(archive(names=struct.pack('<HH', *lengths) + b'ab', unk=1))

    def test_trailing_bytes_are_not_ignored(self):
        for extra in (b'X', b'\0' * 4, name_entry()):
            with self.subTest(extra_length=len(extra)):
                self.reject(archive(names=name_entry() + extra, unk=1))

    def test_complete_table_count_wraps(self):
        for count in (65535, 65536, 65539):
            for names, unk in ((b'', 0), (name_entry(), 1)):
                with self.subTest(count=count, has_names=bool(names)):
                    self.read_archive(archive(count, names, unk), calls=count)

    def test_bad_headers_and_table_bounds(self):
        valid = archive()
        footer_begin = len(valid) - FOOTER.size
        for data in (b'', b'\0' * 23, replace_footer(valid, magic=0),
                     replace_footer(valid, end=footer_begin + 1),
                     replace_footer(valid, table=footer_begin + 1),
                     replace_footer(valid, end=0),
                     replace_footer(valid, table=0xffffffff, end=0xffffffff),
                     replace_footer(valid, count=2)):
            with self.subTest(data=data[-24:]):
                self.reject(data)

    def test_existing_entry_validation_precedes_all_callbacks(self):
        original = archive(count=2, names=name_entry(), unk=1)
        second = len(PAYLOAD) + ENTRY.size + len(ARCHIVE) + len(FILENAME)
        mutations = [(0, '<H', 0), (0, '<H', 65535), (18, '<H', 0),
                     (6, '<I', len(PAYLOAD) + 1), (14, '<I', len(PAYLOAD) + 1)]
        for offset, fmt, value in mutations:
            with self.subTest(offset=offset, value=value):
                bad = bytearray(original)
                struct.pack_into(fmt, bad, second + offset, value)
                self.reject(bytes(bad))
        bad = bytearray(original)
        bad[second + ENTRY.size] = 0
        self.reject(bytes(bad))
        # A final table fragment, even after a valid entry, must fail first.
        single = archive()
        fragment = single[:-24] + b'X' + single[-24:]
        self.reject(replace_footer(fragment, end=len(fragment) - 24))

    def test_callback_failure_is_propagated(self):
        self.read_archive(archive(count=3, names=name_entry(), unk=1),
                          expected=False, calls=2, fail_at=2)

    def test_cli_roundtrip_leaves_name_list_inert(self):
        compressor = zlib.compressobj(wbits=-15)
        compressed = compressor.compress(PAYLOAD) + compressor.flush()
        for names, unk in ((b'', 1115), (name_entry(), 1)):
            with self.subTest(has_names=bool(names)), tempfile.TemporaryDirectory(
                    prefix='ipf-cli-test-') as directory:
                cwd = Path(directory)
                path = cwd / 'test.ipf'
                original = archive(names=names, unk=unk, payload=compressed)
                path.write_bytes(original)
                sentinel = cwd / 'extract/old.ipf/directory/old.lua'
                sentinel.parent.mkdir(parents=True)
                sentinel.write_bytes(b'keep')
                for action in ('encrypt', 'decrypt', 'extract'):
                    result = subprocess.run([str(self.cli), str(path), action, 'lua'],
                                            cwd=cwd, capture_output=True, timeout=20)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(path.read_bytes()[len(compressed):],
                                     original[len(compressed):])
                self.assertEqual(path.read_bytes(), original)
                self.assertEqual((cwd / 'extract/data.ipf/payload.lua').read_bytes(), PAYLOAD)
                self.assertEqual(sentinel.read_bytes(), b'keep')
                files = sorted(p.relative_to(cwd / 'extract').as_posix()
                               for p in (cwd / 'extract').rglob('*') if p.is_file())
                self.assertEqual(files, ['data.ipf/payload.lua', 'old.ipf/directory/old.lua'])

    def test_cli_rejects_malformed_list_before_decrypt_or_extract(self):
        original = archive(names=name_entry() + b'X', unk=1)
        for action in ('decrypt', 'extract'):
            with self.subTest(action=action), tempfile.TemporaryDirectory(
                    prefix='ipf-cli-invalid-') as directory:
                cwd = Path(directory)
                path = cwd / 'bad.ipf'
                path.write_bytes(original)
                result = subprocess.run([str(self.cli), str(path), action, 'lua'],
                                        cwd=cwd, capture_output=True, timeout=20)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(path.read_bytes(), original)
                self.assertFalse(any(p.is_file() for p in (cwd / 'extract').rglob('*')))


if __name__ == '__main__':
    unittest.main()
