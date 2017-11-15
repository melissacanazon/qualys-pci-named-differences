# qualys-pci-named-differences
reports new vulnerabilities discovered between 2 PCI scans, and whether the vulnerability was a false positive
(basically automate the boring stuff)

'-D', '--Debug', help='Debug Mode assists in determining issues being raised by the script.', action='store_true'
'-F', '--firstScan', help='first scan (original scan)'
'-N', '--newScan', help='new scan'
'-fP', '--falsePositives', help='false positives file'
'-V', '--vulnerabilitiesFile', help='path and name of new vulnerabilities file'
