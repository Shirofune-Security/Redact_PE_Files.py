#!/usr/bin/python
# -*- coding: utf-8 -*-

#Author: Isaac Mathis、白船
#2018-10-04
#Version 1.0
#Description:
#Tool to redact (overwrite the .text,.data,etc.. segments of all PE files in a hard drive DD image to not violate any redistribution license agreements when distributing for forensics contests, training, etc..)
#It redacts on the file layer so metadata, etc.. is not changed.
#However, if the disk is fragmented it will most likely overwrite over OS files, important evidence, etc.. so it is best to defrag the disk before creating the forensics scenario. It is also possible to defrag the disk later by mounting with something like OSFMount then defrag but ideal to defrag before creating the evidence.
#If you want to plant any pseudo-malware in the image, just change the dos error msg in the binary so this tool skips over it. Then change it back if you want to.
#
#I have had luck with completely defragging a NTFS partition by using a combination of UltraDefrag's complete disk optimization and Sysinternal's contig tool on all the files,
#resulting in non-corrupted redacted dd images. 
#It takes about 3 hours to redact a 10GB image in artistic mode with a SSD.
#The random art is UTF-8 so is funny to see but alot of tools can not display UTF-8 so feel free to change to all ASCII art.

#Usage: python3 redact_PE_files.py redact_this_image.dd

import os 
import struct
import sys
from time import time, strftime, localtime
from datetime import timedelta
import random

###########################################################

def human_readable_size(num, suffix='B'):
    for unit in ['',' K',' M',' G',' T',' P',' E',' Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def secondsToStr(elapsed=None):
    if elapsed is None:
        return strftime("%Y-%m-%d %H:%M:%S", localtime())
    else:
        return str(timedelta(seconds=elapsed))

def get_art():
   random_art = ['ô¿ô','Ƹ̵̡Ӝ̵̨̄Ʒ', '(Ο_Ο)','°º¤ø,¸¸,ø¤º°`°º¤ø,¸,ø¤°º¤ø,¸¸,ø¤º°`°º¤ø,¸','╭∩╮','[{-_-}] ZZZzz zz z...','٩(̾●̮̮̃̾•̃̾)۶','(^_^)', '[o_o]', '(^.^)','v～。～', '($.$)','﴾ ̲◦̲ / ̅•̅ ﴿        ̮ ‿(   ́ ̵ _-`)‿ ̮', 'Ω ≠ ॐ       −◡(   ́○ ̖_◦`)◡−','ґ°°ґôــôl <˚˚<סּـۧـסּ>	(º„º(ôـ۠ـ۠ـ۠ـô) /°°/ōـۡـō\ l˚≡˚lـ۫סּ۫ــ۫ــ۫ــ۫סּ۫ـl ‹°°‹ôـ۬ـô› ґ˚˚ґōـۤـۤـōì ٵ ۫ ۫ ٵõۢـــۢõl    !!!?!@#*ffuu!!!?!??!!!!!','[ ▇ ▄ ▅ █ ▇ ▂ ▃ ▁ ▄ ▅ █ ▅ ▇ ]','c[○┬●]כ ','c[■┬□]כ','││└┘ (< ◦ ◦ ● ◦ ◦ ⌠∙∙ì ⌠∙∙ì ┌┐││', 'зٰٰ═( ^ ~ ^)═ٰٰε', '│   │  |  ׀  י  ▫  י  ׀  |  │  |̵o̵|  ﴾̵ ̵©̵ ̵﴿  |̵o̵|  │   │', '♪ ♫    ◦◡(ﺀ ՛ˆ̖ ̳ͻ̳ ̗ˆ՝) ̷ ̊└ۜ┘    ♬♩♬♩', 'Σ（￣□￣；）ﾊｯ!!', '☜︎(◉︎ɷ◉︎ )', '(￣(ｴ)￣)ﾉレッツハック～☆', 'HaCK Th3 P1aN3t!!', 'NiNja', '¯＼(º_o)/¯', 'Σ (ﾟДﾟ;）', 'Yamato Security', '白船', '大和セキュリティ']
   return random.choice(random_art)

###########################################################

artistic_mode = True #Change to false if you want to redact as fast as possible. (Just overwrite with one static character. Default: "?")
number_of_arguments = len(sys.argv)

#Check number of arguments
if number_of_arguments != 2:
   print("Usage: python3 ./redact_PE_files.py redact_this_image.dd")
   exit()

redact_this_file = sys.argv[1]
redact_this_file_no_extension, file_extension = os.path.splitext(redact_this_file)

#Check if .dd file
if file_extension != ".dd":
   print("You need to use this on a raw disk image => .dd file")
   exit()

#Check if we can open the file
print("Trying to open: " + redact_this_file)
try:
   f = open(redact_this_file, 'r')
except OSError:
   print('Cannot open file!')
   exit()
else:
   f.close()


filesize = os.path.getsize(redact_this_file)
print("Redacting all PE files in: " + redact_this_file + "  (" + human_readable_size(filesize) + ")")

MZ_string_found = 0
corrupt_PE_files = 0
PE_files = 0
absolute_offset = 0

binary_file = open(redact_this_file, "r+b")

print("Started Redacting: " + secondsToStr())
print("")

start_time = time()

fourth_done = int(filesize * .25)
fourth_done_bool = False
half_done = int(filesize * .5)
half_done_bool = False
third_done = int(filesize * .75)
third_done_bool = False

#Going to town.
while absolute_offset < filesize:
      binary_file.seek(absolute_offset)
      first_byte = binary_file.read(1)   
      if first_byte == b'M':
         second_byte = binary_file.read(1)
         if second_byte == b'Z':
            MZ_string_found += 1
            binary_file.seek(76,1) #Skip 76 bytes to 78th (0x48) offset, should be the dos error msg string (Minus 2 for MZ -> 76)
            dos_error_msg = binary_file.read(39)
            if dos_error_msg == b'This program cannot be run in DOS mode.': 
               binary_file.seek(-57,1) #skip backwards to AddressOfNewExeHeader
               PE_header_offset = struct.unpack('<l', binary_file.read(4)) #read 4 bytes of AddressOfNewExeHeader (long=4bytes little endian)
               PE_header_offset_int = PE_header_offset[0]
               binary_file.seek(absolute_offset) #reset the offset to the beginning of the PE file
               binary_file.seek(PE_header_offset_int,1) #skip ahead to "PE"
               check_PE_string = binary_file.read(2)
               if check_PE_string == b'PE':
                  PE_files += 1
                  binary_file.seek(18,1)
                  Size_of_optional_header_tuple = (struct.unpack('<h',binary_file.read(2)))
                  Size_of_optional_header_int = Size_of_optional_header_tuple[0]
                  binary_file.seek(6,1) #skip to optional header to SizeOfCode
                  Size_of_code = (struct.unpack('<l',binary_file.read(4)))
                  Size_of_code_int = Size_of_code[0]
                  Size_of_initialized_data = (struct.unpack('<l',binary_file.read(4)))
                  Size_of_initialized_data_int = Size_of_initialized_data[0]
                  binary_file.seek(Size_of_optional_header_int-12,1) #skip over optional header to .text
                  codesize = Size_of_code_int + Size_of_initialized_data_int
                  if artistic_mode == False:
                     binary_file.write(b'?' * codesize)

                  if artistic_mode == True:
                     written_data = 0
                     while written_data < codesize:
                        difference = codesize - written_data
                        random_art = bytes(get_art(), 'utf-8')
                        random_art_length = len(random_art)
                        if random_art_length < difference:
                           binary_file.write(random_art)
                           written_data += random_art_length
                        elif random_art_length >= difference and difference > 0:
                           for index in range(0, difference):
                              binary_file.write(bytes(random_art[index]))
                           written_data += difference   
 
                  absolute_offset = binary_file.tell()-1 #continue seeking from the end of the file 
               else:
                  corrupt_PE_files += 1
      if absolute_offset > fourth_done and fourth_done_bool == False:
         print("25% Done. (Time: " + strftime("%H:%M:%S", localtime()) + " Elasped Time: " + secondsToStr(time() - start_time) + ")")
         fourth_done_bool = True
      if absolute_offset > half_done and half_done_bool == False:
         print("50% Done. (Time: " + strftime("%H:%M:%S", localtime()) + " Elasped Time: " + secondsToStr(time() - start_time) + ")")
         half_done_bool = True
      if absolute_offset > third_done and third_done_bool == False:
         print("75% Done! (Time: " + strftime("%H:%M:%S", localtime()) + " Elasped Time: " + secondsToStr(time() - start_time) + ")" + " Almost there! あともう少しだ～！)")
         print("")
         third_done_bool = True
      absolute_offset += 1
     
binary_file.close()

end_time = time()
elapsed_time = end_time - start_time
print("Finished: " + secondsToStr())
print("Elapsed time: " + secondsToStr(elapsed_time))
print("")

print("PE files redacted: " + str(PE_files))
print("Corrupt PE Files: " + str(corrupt_PE_files)) #Files with "This program cannot be run in DOS mode" but no "PE" magic.


