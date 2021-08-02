# 1. Prime Extravaganza 

![Giới thiệu](/2021_UIUCTF/images/h1.PNG "Prime Extravaganza")

Flag của challenge này sẽ là mã hash MD5 của tổng 5 số nguyên tố hợp lệ.

Load file vào IDA để phân tích.

![Load vào IDA](/2021_UIUCTF/images/h2.PNG "Load vào IDA")

Đầu tiên, chương trình sẽ yêu cầu nhập một số bất kì và kiểm tra tính hợp lệ (0 < số nguyên tố < 1000000).

Tiếp theo, gọi hàm **getMaxPrimeFactor()** để tìm số nguyên tố lớn nhất, sau đó in ra màn hình. Đây là một đoạn code rác, không tác động gì đến luồng chính.

Cuối cùng, sẽ thực hiện vòng lặp và kiểm tra số nhập vào có bằng **v9** hay không.

Ta để ý ở đây, **v9** được tính là `19753 * (j + 1)`. 

Vì vậy các số hợp lệ tương ứng là: 19753*5, 19753*4, 19753*3, 19753*2, 19753*1.

Suy ra, flag sẽ là *uiuctf{627360eb8aa0da45ff04a514dab40e54}*


# 2. Tedious

![Giới thiệu](/2021_UIUCTF/images/h3.PNG "Tedious")

Load file vào IDA để phân tích.

![Load vào IDA](/2021_UIUCTF/images/h4.PNG "Tedious")

Luồng chương trình rất rõ ràng, nhập flag vào, và sử dụng các phép toán cộng, trừ, xor để mã hóa flag.

Sau đó sẽ kiểm tra flag với một mảng kí tự.

Vì vậy, tôi sẽ viết script python để brute force flag.

```python
length = 39
enc = [77, 185, 77, 11, 212, 102, 227, 41, 184, 77, 223, 102, 184, 77, 14, 196, 223, 212, 20, 59, 223, 102, 44, 20, 71, 223, 183, 184, 183, 223, 71, 77, 164, 223, 50, 184, 234, 245, 146]
flag = ""

for i in range(length):
    for character in range(0x20, 0x7f):

        tmp = character

        character = (character + 59) ^ 0x38

        character = (character + 18) ^ 0xFD

        character = (character + 4) ^ 0x50

        character = (character + 19) ^ 0x68

        character = (character + 12) ^ 0x79

        if (character - 68) < 0:
            character = 0xFFFFFFFF + ((character - 68) ^ 0xFFFFFFA0) + 1
        else:
            character = (character - 68) ^ 0xA0

        character = (character + 10) ^ 0xcD

        if (character - 72) < 0:
            character = 0xFF + ((character - 72) ^ 0x5A) + 1
        else:
            character = (character - 72) ^ 0x5A

        character = (character + 11) ^ 0xBD

        if (character - 0x1F) < 0:
            character = 0xFFFFFFFF + ((character - 0x1F) ^ 0xFFFFFFED) + 1
        else:
            character = (character - 0x1F) ^ 0xED

        character = (character + 69) ^ 0x22

        if (character - 0x42) < 0:
            character = 0xFF + ((character - 0x42) ^ 0x6B) + 1
        else:
            character = (character - 0x42) ^ 0x6B

        if (character - 0x26) < 0:
            character = 0xFF + ((character - 0x26) ^ 0x6b) + 1
        else:
            character = (character - 0x26) ^ 0x6b

        character = (character + 118) ^ 0xfa

        character = (character + 22) ^ 0x6b

        if (character - 0x4b) < 0:
            character = 0xFF + ((character - 0x4b) ^ 0x6b) + 1
        else:
            character = (character - 0x4b) ^ 0x6b 

        if (character - 0x73) < 0:
            character = 0xFF + ((character - 0x73) ^ 0x64) + 1
        else:
            character = (character - 0x73) ^ 0x64

        character = (character + 10) ^ 0xab

        character = (character + 99) ^ 0x1b

        if (character - 0x2b) < 0:
            character = 0xFFFFFFFF + ((character - 0x2b) ^ 0xFFFFFFF0) + 1
        else:
            character = (character - 0x2b) ^ 0xF0

        character = ((character + 117) ^ 0x6b) & 0xFF

        # check
        if character == enc[i]:
            flag += chr(tmp)
            print("done index " + str(i))
            break

print(flag)
```
Flag là: *uiuctf{y0u_f0unD_t43_fl4g_w0w_gud_j0b}*


# 3. signals

![Giới thiệu](/2021_UIUCTF/images/h5.PNG "signals")

Load file vào IDA để phân tích.

![Load vào IDA](/2021_UIUCTF/images/h6.PNG "signals")

Flag sẽ được đọc vào bằng cách truyền tham số cho chương trình.

Đầu tiên, chương trình sẽ gọi hàm **make_executable()** để làm cho hàm **code()** đang được chứa ở **.data** section.

Tiếp theo, gọi hàm **fork()** để tạo một child process. Process này sẽ thực thi hàm **code()**, còn parent process sẽ lắng nghe signal của child process.

![Load vào IDA](/2021_UIUCTF/images/h7.PNG "signals")

Tại hàm **code()**, ta sẽ chú ý, rcx sẽ chứa địa chỉ flag. Hàm này sẽ thực hiện việc giải mã lại một vùng data bằng xor với key là một kí tự đầu tiên của flag, sau đó nhảy đến vùng đã được giải mã để thực thi.

Tôi đoán kí tự đó sẽ là "*u*", tôi thử giải mã, và nhận được một đoạn code giống với hàm **code()**. Nhưng key sẽ là kí tự tiếp theo của flag.

Vì vậy, tôi đã viết một đoạn script python để thực thi trong ida.

```python
addr = 0x4f77  # thay đổi addr mỗi lần giải mã

import idc
key = idc.get_wide_byte(addr) ^ 0x48
for ea in range(addr, addr + 0x1d, 1):
	idc.patch_byte(ea, idc.get_wide_byte(ea) ^ key)
print(chr(key), end='')
```

Flag là: *uiuctf{another_ctf_another_flag_checker}*


# 4. 


