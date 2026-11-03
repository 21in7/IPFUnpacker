/**
 *
 *   ██████╗   ██╗ ███████╗ ███╗   ███╗ ██╗   ██╗
 *   ██╔══██╗ ███║ ██╔════╝ ████╗ ████║ ██║   ██║
 *   ██████╔╝ ╚██║ █████╗   ██╔████╔██║ ██║   ██║
 *   ██╔══██╗  ██║ ██╔══╝   ██║╚██╔╝██║ ██║   ██║
 *   ██║  ██║  ██║ ███████╗ ██║ ╚═╝ ██║ ╚██████╔╝
 *   ╚═╝  ╚═╝  ╚═╝ ╚══════╝ ╚═╝     ╚═╝  ╚═════╝
 *
 * @license GNU GENERAL PUBLIC LICENSE - Version 2, June 1991
 *          See LICENSE file for further information
 */

#include "ipf.h"
#include "dbg/dbg.h"
#include <string.h>

#pragma pack (push, 1)
typedef struct {
    uint16_t fileCount;
    uint32_t filetableOffset;
    uint16_t unk;
    uint32_t filefooterOffset;
    uint32_t magic;
    uint32_t baseRevision;
    uint32_t revision;
} ArchiveHeader;
#pragma pack (pop)

#pragma pack (push, 1)
typedef struct {
    uint16_t filenameLength;
    uint32_t crc;
    uint32_t compressedLength;
    uint32_t uncompressedLength;
    uint32_t dataOffset;
    uint16_t archivenameLength;
} IpfInfo;
#pragma pack (pop)

bool ipf_read (uint8_t *ipf, size_t size, IpfCallback callback, void *userdata)
{
    if (!ipf || !callback || size < sizeof(ArchiveHeader)) {
        error ("Truncated IPF archive header.");
        return false;
    }

    ArchiveHeader header;
    memcpy (&header, ipf + size - sizeof(header), sizeof(header));
    const char magic[] = {0x50, 0x4b, 0x05, 0x06};
    if (memcmp (&header.magic, magic, sizeof(magic)) != 0) {
        error ("Wrong magic word : %#x", header.magic);
        return false;
    }

    size_t tableBegin = header.filetableOffset;
    size_t tableEnd = header.filefooterOffset;
    size_t footerBegin = size - sizeof(header);
    if (tableBegin > tableEnd || tableEnd > footerBegin) {
        error ("Invalid IPF file table bounds.");
        return false;
    }

    // Validate the complete table before any callback can write output.
    // The stored uint16_t count wraps for archives containing 65536+ files.
    size_t count = 0;
    for (size_t cursor = tableBegin; cursor < tableEnd; count++) {
        if (tableEnd - cursor < sizeof(IpfInfo)) {
            error ("Truncated IPF file table entry.");
            return false;
        }
        IpfInfo entry;
        memcpy (&entry, ipf + cursor, sizeof(entry));
        size_t namesSize = (size_t) entry.archivenameLength + entry.filenameLength;
        if (!entry.archivenameLength || !entry.filenameLength ||
            namesSize > tableEnd - cursor - sizeof(entry)) {
            error ("Invalid IPF entry name lengths.");
            return false;
        }
        if (entry.dataOffset > tableBegin ||
            entry.compressedLength > tableBegin - entry.dataOffset) {
            error ("Invalid IPF entry data bounds.");
            return false;
        }
        const uint8_t *names = ipf + cursor + sizeof(entry);
        if (memchr (names, '\0', namesSize)) {
            error ("Invalid NUL byte in IPF entry name.");
            return false;
        }
        cursor += sizeof(entry) + namesSize;
    }
    if ((uint16_t) count != header.fileCount) {
        error ("IPF file count does not match its complete table.");
        return false;
    }

    // Some archives place a counted name list between the table and footer.
    // Its meaning is unknown: validate it, but never invoke callbacks for it.
    // An empty interval retains the legacy behavior regardless of header.unk.
    if (tableEnd < footerBegin) {
        size_t cursor = tableEnd;
        for (size_t index = 0; index < header.unk; index++) {
            if (footerBegin - cursor < 4) {
                error ("Truncated IPF name list entry.");
                return false;
            }
            size_t archiveLength = (size_t) ipf[cursor] | ((size_t) ipf[cursor + 1] << 8);
            size_t filenameLength = (size_t) ipf[cursor + 2] | ((size_t) ipf[cursor + 3] << 8);
            cursor += 4;
            size_t namesSize = archiveLength + filenameLength;
            if (namesSize > footerBegin - cursor) {
                error ("Invalid IPF name list lengths.");
                return false;
            }
            cursor += namesSize;
        }
        if (cursor != footerBegin) {
            error ("IPF name list does not end at the footer.");
            return false;
        }
    }

    for (size_t cursor = tableBegin; cursor < tableEnd; ) {
        IpfInfo entry;
        memcpy (&entry, ipf + cursor, sizeof(entry));
        const uint8_t *names = ipf + cursor + sizeof(entry);
        char archive[(size_t) entry.archivenameLength + 1];
        char filename[(size_t) entry.filenameLength + 1];
        memcpy (archive, names, entry.archivenameLength);
        archive[entry.archivenameLength] = '\0';
        memcpy (filename, names + entry.archivenameLength, entry.filenameLength);
        filename[entry.filenameLength] = '\0';

        if (!callback (ipf + entry.dataOffset, entry.compressedLength,
                       archive, filename, userdata)) {
            error ("callback failed for '%s:%s'", archive, filename);
            return false;
        }
        cursor += sizeof(entry) + entry.archivenameLength + entry.filenameLength;
    }
    return true;
}
