# Py-FFChPW2KP1
Simple Python scripts to format exported Firefox and Chrome passwords CSV files for easy import into KeePass v1.

1. Export your passwords as CSV files from Firefox and/or Chrome.
2. Format them into new CSV files with the appropriate Python script.
3. Import the created CSV file as CSV into KeePass v1 (classic).

## CLI command usage:
 - **Firefox**: python FFPwConv.py <ff_creds_exp.csv> <kp1_creds_imp.csv> <ff_export_date>
 -      eg. python FFPwConv.py myFFpasswords.csv myKP1FFpasswords.csv 20230907
  
 - **Chrome** : python ChPwConv.py <ch_creds_exp.csv> <kp1_creds_imp.csv> <ch_export_date>
 -      eg. python ChPwConv.py myChromePasswords.csv myKP1Chpasswords.csv 20230907

Expected *Firefox* export CSV column headers:
  - url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged
  
Expected *Chrome* export CSV column headers:
  - name,url,username,password,note

*Keepass* import headers:
  - "Account","Login Name","Password","Web Site","Comments"


**Enjoy!**
