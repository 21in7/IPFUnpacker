"""Exercise the actual native IES-to-CSV exporter with synthetic string cells."""
import csv
import io
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VALUES = ['plain', 'He said "hello"', 'comma,value', 'line1\nline2', '', '""', '한글 "문자"']
DRIVER = r'''
#define main unpacker_cli_main
#include "src/ipf_unpack/ipf_unpack.c"
#undef main
int main(void) {
    const char *values[]={"plain", "He said \"hello\"", "comma,value", "line1\nline2", "", "\"\"", "한글 \"문자\""};
    IesHeader header={0}; header.colsCount=3; header.rowsCount=7;
    IesColumn columns[3]={0};
    strcpy(columns[0].name,"Text"); columns[0].type=1;
    strcpy(columns[1].name,"Localized"); columns[1].type=2;
    strcpy(columns[2].name,"ID"); columns[2].type=0;
    IesRow rows[7]={0};
    IesCell(0,128) cells[7][3]; memset(cells,0,sizeof(cells));
    IesCell(0,0) *pointers[7][3];
    for(int r=0;r<7;r++) {
        rows[r].cellsCount=3; rows[r].cells=(void *)pointers[r];
        for(int c=0;c<3;c++) {
            cells[r][c].col=&columns[c];
            cells[r][c].optSize=0; cells[r][c].strSize=128;
            if(c<2) strcpy(cells[r][c].str.value,values[r]);
            else cells[r][c].flt.value=(float)(r+1);
            pointers[r][c]=(void *)&cells[r][c];
        }
    }
    IesTable table={.header=&header,.columns=columns,.rows=rows};
    IesParams params={.output=stdout};
    return process_ies(&table,&params)?0:1;
}
'''


class CSVExportTest(unittest.TestCase):
    def test_native_string_cells_roundtrip(self):
        with tempfile.TemporaryDirectory(prefix='ipf-csv-test-') as directory:
            temp = Path(directory)
            driver, executable = temp / 'driver.c', temp / 'csv-test'
            driver.write_text(DRIVER, encoding='utf-8')
            subprocess.run([
                'gcc', '-std=gnu99', '-D_GNU_SOURCE', '-ffunction-sections',
                '-fdata-sections', '-I' + str(ROOT), '-I' + str(ROOT / 'src'),
                '-I' + str(ROOT / 'src/common'), '-Wl,--gc-sections',
                str(driver), '-o', str(executable),
            ], check=True)
            output = subprocess.check_output([str(executable)]).decode('utf-8')
        rows = list(csv.reader(io.StringIO(output, newline=''), strict=True))
        self.assertEqual(rows[0], ['Text', 'Localized', 'ID'])
        self.assertEqual(len(rows), len(VALUES) + 1)
        for index, value in enumerate(VALUES):
            with self.subTest(value=value):
                self.assertEqual(rows[index + 1], [value, value, str(index + 1)])


if __name__ == '__main__':
    unittest.main()
