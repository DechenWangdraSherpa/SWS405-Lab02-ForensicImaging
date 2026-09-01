# LAB 02 - Forensic Imaging

**Name: Dechen Wangdra Sherpa**
**Student ID: 02230281**

**Rooms:**
- https://tryhackme.com/room/volatilityessentials
- https://tryhackme.com/room/forensicimaging
- https://tryhackme.com/room/caseb4dm755

---

## 1. Aim

The aim of this lab was to get comfortable with three different sides of digital forensics: analyzing a live memory dump with Volatility 3, creating and verifying a forensic disk image from scratch, and working through a full "real" case investigation using FTK Imager and exiftool. I wanted to actually understand what each tool is doing under the hood rather than just copy-pasting commands, so I've tried to explain my reasoning at each step below.

## 2. Objectives

- Use Volatility 3 to investigate two separate memory dumps and identify malicious processes, their parent-child relationships, injected code, and hooked system calls.
- Learn the proper procedure for acquiring a forensic disk image (identifying the device, imaging it with `dc3dd`, and verifying its integrity with hashing).
- Walk through a simulated digital forensics case end-to-end — from receiving a search warrant to extracting hidden evidence from files using FTK Imager and exiftool — and understand the legal/procedural steps that surround the technical work.

## 3. What I Understood

**Volatility Essentials:** Volatility 3 doesn't rely on the old profile system from v2 anymore — it works directly off memory layers and symbol tables, and plugins are just how you ask it to pull specific structures out of RAM. What stood out to me is how much you can reconstruct just from a memory snapshot: process trees, loaded DLLs, open handles, even evidence of code injection (`malfind`) and rootkit-style hooking (`ssdt`). It really is a full timeline of what was running on the machine at the moment it was captured.

**Forensic Imaging:** This room made it clear that imaging isn't just "copy the disk" — it's a chain-of-custody-sensitive process. Every step (checking for encryption, using a write-blocker in real scenarios, logging your commands, hashing before and after) exists to make sure the copy is legally defensible. `dc3dd` is basically `dd` with built-in hashing and logging, which is exactly why it's preferred over plain `dd` in this kind of work.

**Case B4DM755:** This was less about a single tool and more about the full DFIR workflow — Pre-search (getting the warrant), Search (seizing and acquiring the evidence), Post-search (actual analysis), and Trial (presenting it properly). On the technical side, I liked how the "hidden" evidence wasn't hidden in some exotic way — it was mislabeled file extensions, a renamed Office file that was secretly a zip, and metadata that gave away information the suspect probably didn't think to scrub. It reinforced that a lot of real forensic work is just being thorough and checking things twice.

## 4. Summary

Across the three rooms I:
- Identified a banking trojan process (`Reader_sl.exe`) in Case 001 and traced its parent process, DLLs, and handles, then confirmed a WannaCry infection (`@WanaDecryptor@`) in Case 002 by tracing its process tree and file path.
- Created a raw forensic image of a virtual disk using `dc3dd`, verified it byte-for-byte against the source device with MD5 hashing, and mounted the resulting image to confirm its contents.
- Worked through the full B4DM755 case: acquired a disk image and flash drive in FTK Imager, recovered deleted and corrupted files, pulled EXIF metadata to identify the phones used to take incriminating photos, cracked a password-protected archive, and recovered a hidden flag buried in a "MUST_CLEAN" folder.

All three rooms were completed. Screenshots for each step are in the evidence section below.

---

## 5. Screenshots / Evidence

### 5.1 Volatility Essentials

**Case 001 — Adobe Trojan**

I started by pulling basic host info from the memory dump to confirm the build version and when the capture was taken.

`python3 vol.py -f Investigation-1.vmem windows.info`

![Screenshot: vol01_windows_info.png](screenshots/vol01_windows_info.png)

*Shows the `NTBuildLab` and `SystemTime` fields — confirms build `2600.xpsp.080413-2111` and acquisition time `2012-07-22 02:45:08`.*

Next, I searched the process tree for anything Adobe-related, since the case hinted at a malicious Adobe document.

`python3 vol.py -f Investigation-1.vmem windows.pstree | grep -i adobe`

![Screenshot: vol02_pstree_adobe.png](screenshots/vol02_pstree_adobe.png)

*Shows the full path `C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe`.*

To find its parent process, I ran a full process scan:

`python3 vol.py -f Investigation-1.vmem windows.psscan`

![Screenshot: vol03_psscan_ppid.png](screenshots/vol03_psscan_ppid.png)

*Shows PID 1484 (Reader_sl.exe) with its PPID pointing to explorer.exe.*

I then checked which DLLs it had loaded outside the usual `system32` directory, since that's often a sign of something unusual:

`python3 vol.py -f Investigation-1.vmem windows.dlllist --pid 1484 | grep -v -i system32`

![Screenshot: vol04_dlllist.png](screenshots/vol04_dlllist.png)

*Shows 3 DLLs loaded from outside system32.*

I also checked its handles for anything unusual:

`python3 vol.py -f Investigation-1.vmem windows.handles --pid 1484 | grep -i keyedevent`

![Screenshot: vol05_handles.png](screenshots/vol05_handles.png)

*Shows the `CritSecOutOfMemoryEvent` KeyedEvent handle.*

To look for actual injected code, I ran `malfind` and filtered for processes flagged with a Windows executable (MZ) header in memory that shouldn't normally have one:

`python3 vol.py -f Investigation-1.vmem windows.malfind | grep -i "mz header"`

![Screenshot: vol06_malfind.png](screenshots/vol06_malfind.png)

*Shows both `explorer.exe` and `reader_sl.exe` flagged with MZ headers.*

Finally, I checked for kernel-level hooking using the SSDT plugin, since this is a common rootkit technique:

`python3 vol.py -f Investigation-1.vmem windows.ssdt`

![Screenshot: vol07_ssdt.png](screenshots/vol07_ssdt.png)

*Shows the hooked `NtCreateFile` entry at address `0x8056e27c`.*

**Case 002 — Ransomware Investigation**

Switching to the second memory dump, I was told a suspicious process was running at PID 740:

`python3 vol.py -f Investigation-2.raw windows.psscan --pid 740`

![Screenshot: vol08_case2_psscan.png](screenshots/vol08_case2_psscan.png)

*Shows the `@WanaDecryptor@` process.*

I then pulled its binary path:

`python3 vol.py -f Investigation-2.raw windows.dlllist --pid 740`

![Screenshot: vol09_case2_dlllist.png](screenshots/vol09_case2_dlllist.png)

*Shows the path `C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe`.*

And traced its parent process:

`python3 vol.py -f Investigation-2.raw windows.pstree --pid 740`

![Screenshot: vol10_case2_pstree.png](screenshots/vol10_case2_pstree.png)

*Shows `tasksche.exe` as the parent process — consistent with the WannaCry ransomware family.*

![Screenshot: vol11_room_complete.png](screenshots/vol11_room_complete.png)

*Room completion screen — 100%.*

---

### 5.2 Forensic Imaging

I started in the Task 2 machine by listing all block devices to find the target drive:

`lsblk -a`

![Screenshot: fi01_lsblk.png](screenshots/fi01_lsblk.png)

*Shows the ~1.1G loop device that matches the disk size given in the task.*

Once I confirmed the device, I imaged it using `dc3dd`, an enhanced version of `dd` that includes built-in hashing and logging:

`sudo dc3dd if=/dev/loop11 of=example1.img log=imaging_loop11.txt`

![Screenshot: fi02_dc3dd_imaging.png](screenshots/fi02_dc3dd_imaging.png)

*Shows the full completion output — sector count, bytes copied, and completion timestamp.*

To confirm the image was a perfect copy, I hashed both the image file and the original device and compared them:

`sudo md5sum example1.img` and `sudo md5sum /dev/loop11`

![Screenshot: fi03_md5_match.png](screenshots/fi03_md5_match.png)

*Shows both hashes matching exactly, confirming integrity.*

For the follow-up exercise, I hashed the provided `exercise.img`:

`sudo md5sum /home/analyst/exercise.img`

![Screenshot: fi04_exercise_md5.png](screenshots/fi04_exercise_md5.png)

*Shows the MD5 hash of exercise.img.*

I then mounted it to check its contents:

```
sudo mkdir -p /mnt/exercise
sudo mount -o loop /home/analyst/exercise.img /mnt/exercise
cat /mnt/exercise/flag.txt
```

![Screenshot: fi05_mount_flag.png](screenshots/fi05_mount_flag.png)

*Shows the recovered flag `THM{mounttt-mounttt-me}`.*

For the practical exercise on the Task 6 machine, I repeated the same imaging and hashing process on the attached 1GB loop device:

```
sudo dc3dd if=/dev/loop4 of=practical.img log=imaging_loop4.txt
sudo md5sum practical.img
sudo md5sum /dev/loop4
```

![Screenshot: fi06_practical_md5.png](screenshots/fi06_practical_md5.png)

*Shows matching hashes for the practical exercise device.*

Then mounted it and read the flag:

```
sudo mkdir -p /mnt/loop4
sudo mount /dev/loop4 /mnt/loop4
cat /mnt/loop4/flag.txt
```

![Screenshot: fi07_practical_flag.png](screenshots/fi07_practical_flag.png)

*Shows the recovered flag `THM{well-done-imaginggggggg}`.*

![Screenshot: fi08_room_complete.png](screenshots/fi08_room_complete.png)

*Room completion screen — 100%.*

---

### 5.3 Digital Forensics Case B4DM755

The first few tasks in this room were about understanding the scenario rather than doing hands-on work — I was told I was acting as a **Forensics Lab Analyst**, assigned the role of **DFIR First Responder**, tasked with gathering **digital artefacts and evidence** under a **search warrant**, and that a **flash drive** was recovered from the suspect's residence. Since these were scenario-comprehension questions with no lab environment involved, I've answered them directly in the room without screenshots.

Once I moved into FTK Imager, I started by checking whether the flash drive had EFS encryption on it:

![Screenshot: case01_efs_check.png](screenshots/case01_efs_check.png)

*Shows the "No EFS encryption detected" result after running Detect EFS Encryption.*

I then created a forensic image of the physical drive (Microsoft Virtual Disk) using Raw (dd) format, filled in the evidence details, and let FTK Imager generate the image:

![Screenshot: case02_image_verify.png](screenshots/case02_image_verify.png)

*Shows the Drive/Image Verify Results window with the SHA1 hash confirming the image matches the source drive.*

Opening the flash drive with hidden items shown in Windows Explorer, I counted all files present:

![Screenshot: case03_file_list_hidden.png](screenshots/case03_file_list_hidden.png)

*Shows all 8 files on the flash drive, including hidden ones.*

Looking back in the File List Pane, I checked for files marked with a red X, which indicates they'd been deleted:

![Screenshot: case04_deleted_files.png](screenshots/case04_deleted_files.png)

*Shows 6 files marked as deleted.*

I then sorted by size to find any recovered files with 0 bytes, which usually means corruption:

![Screenshot: case05_corrupted_files.png](screenshots/case05_corrupted_files.png)

*Shows 3 files with 0 file size.*

Moving into the forensics lab stage, I checked the tools directory on the Desktop and found a second tool alongside FTK Imager:

![Screenshot: case06_tools_dir.png](screenshots/case06_tools_dir.png)

*Shows the `exiftool-12.47` folder.*

I noticed a file called `hideout.pdf` sitting in the root folder. Its extension said PDF, but I wanted to confirm that with metadata, so I exported it and ran exiftool on it:

`exiftool C:\Users\dfir\Desktop\hideout.pdf`

![Screenshot: case07_hideout_exiftool.png](screenshots/case07_hideout_exiftool.png)

*Shows the actual file type is JPEG, not PDF — the extension had been changed to disguise the file.*

Using the Viewer Pane in FTK Imager, I checked the EXIF metadata on the same file to see if it revealed anything about how it was taken:

![Screenshot: case08_phone_hideout.png](screenshots/case08_phone_hideout.png)

*Shows the camera model — ONEPLUS A6013 — used to photograph the hideout.*

I repeated this for `warehouse.pdf`:

![Screenshot: case09_phone_warehouse.png](screenshots/case09_phone_warehouse.png)

*Shows the camera model — Mi 9 Lite — used to photograph the warehouse.*

To dig further into the suspect's activity, I exported `operations.xlsx`, renamed it to `operations.zip`, extracted it, and opened the text file inside:

![Screenshot: case10_operations_notes.png](screenshots/case10_operations_notes.png)

*Shows the 2022 entry listing the point of contact (Karl Renato Abelardo) and GPS coordinates of a meetup (14°26'25.7"N 120°59'00.8"E).* 

While reading through the extracted notes, I came across a password that looked like it belonged to another archive I'd found — `pandorasbox.zip`:

![Screenshot: case11_pandorasbox_pw.png](screenshots/case11_pandorasbox_pw.png)

*Shows the recovered password string used to unlock pandorasbox.zip.*

After extracting the archive with that password, I opened one of the Python source files inside to check where the code had come from:

![Screenshot: case12_source_company.png](screenshots/case12_source_company.png)

*Shows a comment header identifying the source company as SwiftSpend Financial.*

Inside a `MUST_CLEAN` subfolder, I found several Word documents. One of them hadn't been signed yet, and it named a beneficiary:

![Screenshot: case13_beneficiary_doc.png](screenshots/case13_beneficiary_doc.png)

*Shows the trust document naming Mr. Giovanni Vittorio DeVentura as beneficiary.*

Finally, in the root of the extracted pandorasbox folder, there was a file named `DONOTOPEN`. Opening it in Notepad (ignoring the name) revealed the final flag:

![Screenshot: case14_hidden_flag.png](screenshots/case14_hidden_flag.png)

*Shows the flag `THM{sCr0LL_sCr0LL_cL1cK_cL1cK_4TT3NT10N_2_D3T41L5_15_CRUC14L!!}`.*

![Screenshot: case15_room_complete.png](screenshots/case15_room_complete.png)

*Room completion screen — 100%.*

---

## Conclusion

This lab pulled together three different pieces of the DFIR process — live memory analysis, disk imaging, and a full case-style investigation — and I found the case room especially useful for tying the technical work back to the legal/procedural side of forensics (warrants, chain of custody, presenting evidence at trial). Between the three rooms, I got hands-on practice with Volatility 3, `dc3dd`, hashing for integrity verification, and FTK Imager alongside exiftool for metadata analysis.