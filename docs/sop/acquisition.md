# SOP: Evidence Acquisition (draft, Phase 1)

## 1. Preparation
1. Create the case: `forensidvr case create CASE_DIR --name ... --examiner ... --case-number ... --agency ...`
2. Photograph the DVR/NVR, labels, serial numbers, cabling and on-screen clock vs. a reference
   clock (record the offset — it is needed for timeline normalisation).
3. Power down per agency policy; remove the drive(s), recording bay order and serials.

## 2. Physical acquisition (preferred)
1. Connect each drive through a **hardware write-blocker**. The software blocker is not a substitute.
2. Identify the device node (`lsblk -o NAME,SIZE,MODEL,SERIAL`) and record it.
3. Image: `forensidvr acquire disk CASE_DIR /dev/sdX --label "DVR1-HDD1" [--split-size 2G]`
   (run as a user with read access to the device; never mount it).
4. Confirm the output shows `verification: PASS`. Review `reports/acquisition-*.md` for bad sectors.
5. Store the original drive in an evidence bag; record the seal number in the case notes.

## 3. Pre-existing images
`forensidvr evidence add CASE_DIR image.E01 --label ...` hashes the media in place. For E01 the
embedded MD5 is compared automatically and the result recorded.

## 4. Logical acquisition (disk unavailable)
Export clips/config/logs using the device UI or vendor client to clean media, then
`forensidvr acquire logical CASE_DIR /media/usb --label "DVR1 export"`. Record in notes how the
export was produced (tool, version, user account, time range).

## 5. Before every analysis session
`forensidvr session CASE_DIR EV-0001` — refuses to proceed if the hash no longer matches.

## 6. Custody
`forensidvr custody verify CASE_DIR` at the start and end of each working day; exit code 3 means
the log was altered — stop and escalate.
