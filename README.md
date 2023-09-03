# CVE_Reverse_Search
This is a Rust applet that searches a local .xml CVE database for entries based on description tokens. Enjoy

Download a .xml of the CVE here from MITRE: https://cve.mitre.org/data/downloads/index.html

Then you can use this tool to search it. Just pass it a string and let it work. Returns nothing if not found

Just a heads up that the CVE database is monstrous in size so have some disk free.

Also, there is an unsafe block in this code that grabs bytes from the .xml file without checking them for valid UTF-8. Don't be worried about it. If you grab the database directly from MITRE, it's on them to ensure its valid and likely will be.

![image](https://github.com/STashakkori/CVE_Reverse_Search/assets/4257899/34694323-aebf-486d-b2c2-e1f51e038bc7)
