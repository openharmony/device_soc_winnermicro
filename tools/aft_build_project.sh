#!/bin/sh
ProjName=$1
OutPath=$2
ToolPath="./tools"
signature=0
prikey_sel=0
code_encrypt=0
sign_pubkey_src=0
img_type=1
zip_type=1

sec_img_header=8002000
sec_img_pos=8002400
run_img_header=80d0000
run_img_pos=80d0400
upd_img_pos=8010000

echo $ProjName
if [ $prikey_sel -gt 0 ]
 then
  let img_type=$img_type+32*$prikey_sel
fi

if [ $code_encrypt -eq 1 ]
 then
  let img_type=$img_type+16
fi

if [ $signature -eq 1 ]
 then
  let img_type=$img_type+256
fi

if [ $sign_pubkey_src -eq 1 ]
 then
  let img_type=$img_type+512
fi

echo $img_type

if [ $code_encrypt -eq 1 ]
 then
  let prikey_sel=$prikey_sel+1
  openssl enc -aes-128-ecb -in $OutPath/"$ProjName".bin -out $OutPath/"$ProjName"_enc.bin -K 30313233343536373839616263646566 -iv 01010101010101010101010101010101
  openssl rsautl -encrypt -in $ToolPath/key.txt -inkey $ToolPath/ca/capub_"$prikey_sel".pem -pubin -out $OutPath/key_en.dat
  cat $OutPath/"$ProjName"_enc.bin $OutPath/key_en.dat > $OutPath/"$ProjName"_enc_key.bin
  cat $OutPath/"$ProjName"_enc_key.bin $ToolPath/ca/capub_"$prikey_sel"_N.dat > $OutPath/"$ProjName"_enc_key_N.bin  
  $ToolPath/wm_tool -b $OutPath/"$ProjName"_enc_key_N.bin -o $OutPath/"$ProjName" -it $img_type -fc 0 -ra $run_img_pos -ih $run_img_header -ua $upd_img_pos -nh 0  -un 0
 else
  $ToolPath/wm_tool -b $OutPath/"$ProjName".bin -o $OutPath/"$ProjName" -it $img_type -fc 0 -ra $run_img_pos -ih $run_img_header -ua $upd_img_pos -nh 0  -un 0
fi

if [ $signature -eq 1 ]
 then
  openssl dgst -sign  $ToolPath/ca/cakey.pem -sha1 -out $OutPath/"$ProjName"_sign.dat $OutPath/"$ProjName".img
  cat $OutPath/"$ProjName".img $OutPath/"$ProjName"_sign.dat > $OutPath/"$ProjName"_sign.img

  #when you change run-area image's ih, you must remake secboot img with secboot img's -nh address same as run-area image's ih
  $ToolPath/wm_tool -b $ToolPath/w800_secboot.bin -o $ToolPath/w800_secboot -it 0 -fc 0 -ra $sec_img_pos -ih $sec_img_header -ua $upd_img_pos -nh $run_img_header  -un 0    
  cat $ToolPath/w800_secboot.img $OutPath/"$ProjName"_sign.img > $OutPath/"$ProjName".fls  
 else  
  #when you change run-area image's ih, you must remake secboot img with secboot img's -nh address same as run-area image's ih
  $ToolPath/wm_tool -b $ToolPath/w800_secboot.bin -o $ToolPath/w800_secboot -it 0 -fc 0 -ra $sec_img_pos -ih $sec_img_header -ua $upd_img_pos -nh $run_img_header  -un 0  
  cat $ToolPath/w800_secboot.img $OutPath/"$ProjName".img > $OutPath/"$ProjName".fls
fi

#produce compressed ota firmware*/
if [ $zip_type -eq 1 ]
 then
  if [ $signature -eq 1 ]
   then
    $ToolPath/wm_tool -b $OutPath/"$ProjName"_sign.img -o $OutPath/"$ProjName"_sign -it $img_type -fc 1 -ra $run_img_pos -ih $run_img_header -ua $upd_img_pos -nh 0  -un 0
    mv $OutPath/"$ProjName"_sign_gz.img $OutPath/"$ProjName"_sign_ota.img
  else
   $ToolPath/wm_tool -b $OutPath/"$ProjName".img -o $OutPath/"$ProjName" -it $img_type -fc 1 -ra $run_img_pos -ih $run_img_header -ua $upd_img_pos -nh 0  -un 0
   mv $OutPath/"$ProjName"_gz.img $OutPath/"$ProjName"_ota.img
  fi
fi
#openssl --help