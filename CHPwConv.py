#!/usr/bin/env python3
#
# Convert UN/PW exports from Chrome to KeePass v1.
# (c) Ian Neill, 2023.
#
# https://keepass.info/help/base/importexport.html

import csv
import sys

def main():
    if len(sys.argv) != 4:
        print("Usage: %s <ch_creds_exp.csv> <kp1_creds_imp.csv> <ch_export_date>" %  sys.argv[0], file=sys.stderr)
        exit(1)

    csvFilenameIn = sys.argv[1]
    csvFilenameOut = sys.argv[2]
    chExportDate = sys.argv[3]

    print("In file :", csvFilenameIn)
    print("Out file:", csvFilenameOut)
    print("Exported:", chExportDate)

    with open(csvFilenameIn, 'rt') as myCHCSVFile:
        # Field names will be determined from first row.
        csvReader = csv.DictReader(myCHCSVFile)
        # Read everything in one go.
        chPasswords = list(csvReader)

    # Look at what we have got from Chrome.
    print("Number of CH Passwords:", len(chPasswords))
    keePass1List = [] # An empty list for the KP UN/PW dicts.
    # Keepass headers: "Account","Login Name","Password","Web Site","Comments"
    # Chrome headers : name,url,username,password,note
    problemCounter = 0
    for chRow in chPasswords:
        # Looking for Chrome UN/PW details about http or https sites.
        if "http" in chRow['url']:
            keePass1Dict ={} # Create an empty dict for the parsed Chrome UN/PW details.
            keePass1Dict['Account'] = chRow['name']
            keePass1Dict['Login Name'] = chRow['username']
            keePass1Dict['Password'] = chRow['password']
            # Basic checks for potential UN trouble.
            if len(keePass1Dict['Login Name']) == 0:
                keePass1Dict['Login Name'] = "Not Defined!"
            elif keePass1Dict['Login Name'].isdigit() and keePass1Dict['Login Name'][0] == "0":
                problemCounter += 1
                print("  -> Check U-name #%03d: UN  = %s  (leading zero)" % (chPasswords.index(chRow) + 1, keePass1Dict['Login Name']))
            # Basic checks for potential PW trouble.
            if len(keePass1Dict['Password']) == 0:
                keePass1Dict['Password'] = "Not Defined!"
                problemCounter += 1
                print("  -> No P-word! #%03d: %s" % (chPasswords.index(chRow) + 1, keePass1Dict['Password']))
            elif keePass1Dict['Password'].isdigit() and keePass1Dict['Password'][0] == "0":
                problemCounter += 1
                print("  -> Check P-word #%03d: PW  = %s  (leading zero)" % (chPasswords.index(chRow) + 1, keePass1Dict['Password']))
            if '"' in  keePass1Dict['Password']: 
                problemCounter += 1
                print("  -> Check P-word #%03d: PW  = %s  (contains a double-quote)" % (chPasswords.index(chRow) + 1, keePass1Dict['Password']))
            # Getting the KP Web Site field.
            keePass1Dict['Web Site'] = chRow['url']
            # Getting the KP comment field.
            if len(chRow['note']) == 0:
                keePassComments = ""
            else:
                keePassComments = chRow['note'] + "\r\n\r\n"
            keePassComments += "Exported from Chrome %s" % chExportDate
            keePass1Dict['Comments'] = keePassComments # Put the final KP comment in the KP UN/PW dict.
            keePass1List.append(keePass1Dict) # Add the KP UN/PW dict to the KP list of dicts.
        else:
            print("  -> Bad CH Site! #%03d: URL = %s  (ignored)" % (chPasswords.index(chRow) + 1, chRow['url']))
    # Looking for duplicate UN/PW entries in the KP details.
    dupCounter1 = 0
    for kp1EntryA in range(len(keePass1List) - 1):        
        dupCounter2 = 0
        for kp1EntryB in range(kp1EntryA + 1, len(keePass1List)):
            if (keePass1List[kp1EntryA]['Account'] == keePass1List[kp1EntryB]['Account']
                and keePass1List[kp1EntryA]['Login Name'] == keePass1List[kp1EntryB]['Login Name']
                and keePass1List[kp1EntryA]['Password'] == keePass1List[kp1EntryB]['Password']):
                if dupCounter2 == 0:
                    print("  -> Checking KP UN/PW #%03d..." % (kp1EntryA + 1))
                    print("     # Original   #%03d: %s, %s, %s, %s" % (kp1EntryA + 1, keePass1List[kp1EntryA]['Account'], keePass1List[kp1EntryA]['Login Name'], keePass1List[kp1EntryA]['Password'], keePass1List[kp1EntryA]['Web Site']))
                dupCounter1 += 1
                dupCounter2 += 1
                problemCounter += 1
                print("     # Duplicate  #%03d: %s, %s, %s, %s" % (kp1EntryB + 1, keePass1List[kp1EntryB]['Account'], keePass1List[kp1EntryB]['Login Name'], keePass1List[kp1EntryB]['Password'], keePass1List[kp1EntryB]['Web Site']))
    # And now for some totals...
    if problemCounter:
        print("Number of CH PW issues:", problemCounter)
    print()
    print("Number of KP Passwords:", len(keePass1List))
    print("Duplicate KP Passwords:", dupCounter1)

    # write out the KP formatted UN/PW details.
    with open(csvFilenameOut, 'wt', newline='') as myKP1CSVFile:
        # Field names will be determined from first row.
        # Fields will always be contained in quotes and contained quotes will be escaped with a backslash and not double-quoted.
        csvWriter = csv.DictWriter(myKP1CSVFile, fieldnames=keePass1List[0].keys(), quoting=csv.QUOTE_ALL, escapechar="\\", doublequote=False)
        csvWriter.writeheader()
        # Write everything in one go.
        csvWriter.writerows(keePass1List)

if __name__ == '__main__':
    main()

# EOF