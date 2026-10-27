iOS ImageIO null directory rendering bug triggered by malformed UltraHDR XMP/MPF metadata in a JPEG. 
Advertises a gain-map image that is missing or located beyond the end of the file. ImageIO mishandles this condition and passes an invalid object to CFDataGetBytePtr, resulting in a null/invalid-pointer dereference.
Works on platforms such as Kakaotalk or Discord.

Fixed in iOS 26.6. Also similar as CVE-2026-64693.
Still works in MacOS tahoe 26.7.2, which is the latest version

Usage: `python3 ex.py <input JPEG directory> <output JPEG directory>`

Have fun :3
