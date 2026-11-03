# IPFUnpacker
 - Usage : ipf_unpack.exe \<IPF file\> [decrypt/encrypt/extract]

#### IPF table and footer
The data table ends at the stored footer offset. If bytes follow it before the
24-byte footer at EOF, they must contain exactly the footer's `unk` count of
entries: little-endian `uint16 archiveNameLength`, `uint16 filenameLength`, then
the archive and filename bytes. Every entry must fit and the list must end exactly
at the footer; malformed lists are rejected before any data callback runs.
An empty interval remains valid regardless of `unk`, as in the legacy format.
The list's meaning is unknown. It is only validated, never extracted or used to
delete files. Existing data-table validation and wrapped 16-bit file counts remain
unchanged.

#### "decrypt" feature
Decrypt feature will **replace** the encrypted IPF in argument by the decrypted one.  
Make sure to backup your IPF files somewhere before decrypting them.  
Make sure not decrypting twice the same IPF.  
Once decrypted, the IPF is readable by traditional tools (such as IPF Suite).  

#### "encrypt" feature
Encrypt will restore a decrypted IPF in argument to an encrypted one.  
Make sure not encrypting twice the same IPF.  

#### "extract" feature
Extract takes a decrypted IPF as argument and generates a list of files.
By default, some extension files aren't decrypted entirely ; In that case, only the MD5 of the decrypted is generated.
You can use the optional last arguments to notify which extensions you would like to decompress. (e.g : `ipf_decrypt.exe SumAni.ipf extract lua xml` will extract only lua and xml files inside SumAni.ipf)

![HowTo](http://i.imgur.com/UJzXDZN.gif)
