#!/usr/bin/env python3
#
# Convert UN/PW exports from Firefox to KeePass v1.
# (c) Ian Neill, 2023.
#
# https://keepass.info/help/base/importexport.html
# https://blog.bilak.info/2021/04/02/moving-passwords-from-firefox-lockwise-to-keepassxc/

import csv
import sys
from datetime import datetime

def main():
    if len(sys.argv) != 4:
        print("Usage: %s <ff_creds_exp.csv> <kp1_creds_imp.csv> <ff_export_date>" % sys.argv[0], file=sys.stderr)
        exit(1)

    csvFilenameIn = sys.argv[1]
    csvFilenameOut = sys.argv[2]
    ffExportDate = sys.argv[3]

    print("In file :", csvFilenameIn)
    print("Out file:", csvFilenameOut)
    print("Exported:", ffExportDate)

    with open(csvFilenameIn, 'rt') as myFFCSVFile:
        # Field names will be determined from first row.
        csvReader = csv.DictReader(myFFCSVFile)
        # Read everything in one go.
        ffPasswords = list(csvReader)

    # Look at what we have got from Firefox.
    print("Number of FF Passwords:", len(ffPasswords))
    keePass1List = [] # An empty list for the KP UN/PW dicts.
    # Keepass headers: "Account","Login Name","Password","Web Site","Comments"
    # FireFox headers: url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
    problemCounter = 0
    for ffRow in ffPasswords:
        # Looking for Firefox UN/PW details about http or https sites.
        if "http" in ffRow['url']:
            keePass1Dict ={} # Create an empty dict for the parsed Firefox UN/PW details.
            keePass1Dict['Account'] = ffRow['url']
            keePass1Dict['Login Name'] = ffRow['username']
            keePass1Dict['Password'] = ffRow['password']
            # Basic checks for potential UN trouble.
            if len(keePass1Dict['Login Name']) == 0:
                keePass1Dict['Login Name'] = "Not Defined!"
            elif keePass1Dict['Login Name'].isdigit() and keePass1Dict['Login Name'][0] == "0":
                problemCounter += 1
                print("  -> Check U-name #%03d: UN  = %s  (leading zero)" % (ffPasswords.index(ffRow) + 1, keePass1Dict['Login Name']))
            # Basic checks for potential PW trouble.
            if len(keePass1Dict['Password']) == 0:
                keePass1Dict['Password'] = "Not Defined!"
                problemCounter += 1
                print("  -> No P-word! #%03d: %s" % (ffPasswords.index(ffRow) + 1, keePass1Dict['Password']))
            elif keePass1Dict['Password'].isdigit() and keePass1Dict['Password'][0] == "0":
                problemCounter += 1
                print("  -> Check P-word #%03d: PW  = %s  (leading zero)" % (ffPasswords.index(ffRow) + 1, keePass1Dict['Password']))
            if '"' in  keePass1Dict['Password']:
                problemCounter += 1
                print("  -> Check P-word #%03d: PW  = %s  (contains a double-quote)" % (ffPasswords.index(ffRow) + 1, keePass1Dict['Password']))
            # Getting the KP Web Site field from the best FF field.
            if ffRow['formActionOrigin'] != "":
                keePass1Dict['Web Site'] = ffRow['formActionOrigin']
            else:
                keePass1Dict['Web Site'] = ffRow['url']
            # Lets dump other useful FF fields in the KP comment field.
            keePassComments = "Created: %s\r\nLast Used: %s\r\nLast Changed: %s\r\n\r\nExported from FireFox %s" % \
                            (datetime.fromtimestamp(int(ffRow['timeCreated'])/1000).isoformat(),
                             datetime.fromtimestamp(int(ffRow['timeLastUsed'])/1000).isoformat(),
                             datetime.fromtimestamp(int(ffRow['timePasswordChanged'])/1000).isoformat(),
                             ffExportDate)
            # Looking for any potential Account and Web Site name mismatches.
            if keePass1Dict['Account'] != keePass1Dict['Web Site']:
                problemCounter += 1
                print("  -> Check FF Row #%03d: UN  = %s, A/C:%s, WWW:%s  (mismatch)" % (ffPasswords.index(ffRow) + 1, keePass1Dict['Login Name'], keePass1Dict['Account'], keePass1Dict['Web Site']))
            # Prepend the FF httpRealm field, if it exists, to the KP comment field.
            if ffRow['httpRealm'] != "":
                problemCounter += 1
                print("  -> Check FF Row #%03d: RLM = %s  (useful?)"% (ffPasswords.index(ffRow) + 1, ffRow['httpRealm']))
                keePassComments = ffRow['httpRealm'] + "\r\n\r\n" + keePassComments
            keePass1Dict['Comments'] = keePassComments # Put the final KP comment in the KP UN/PW dict.
            keePass1List.append(keePass1Dict) # Add the KP UN/PW dict to the KP list of dicts.
        else:
            print("  -> Bad FF Site! #%03d: URL = %s  (ignored)" % (ffPasswords.index(ffRow) + 1, ffRow['url']))
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
        print("Number of FF PW issues:", problemCounter)
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