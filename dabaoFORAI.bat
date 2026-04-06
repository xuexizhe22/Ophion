<# :
@echo off
cd /d "%~dp0"
set "OUTPUT=源码打包_无乱码版.txt"
echo 当前目录: %cd%
echo 正在扫描并处理编码 (自动识别 GBK / UTF-8 无BOM / UTF-8 BOM)...

rem 将当前脚本作为 PowerShell 执行
powershell -NoProfile -Command "Invoke-Command -ScriptBlock ([scriptblock]::Create((Get-Content -LiteralPath '%~f0' -Raw)))"

echo.
echo 打包完成！生成文件: %OUTPUT%
pause
exit /b
#>

# ================= 以下是 PowerShell 逻辑 =================
$OutFile = "源码打包_无乱码版.txt"
$utf8BOM = New-Object System.Text.UTF8Encoding($true)
$gbk = [System.Text.Encoding]::GetEncoding('gbk')
$allContent = New-Object System.Collections.Generic.List[string]

$files = Get-ChildItem -Path . -Include *.cpp,*.h,*.hpp,*.c,*.lua,*.asm,*.bat -Recurse -File -ErrorAction SilentlyContinue

foreach ($f in $files) {
    # 忽略输出文件本身，防止重复套娃读取
    if ($f.Name -eq $OutFile) { continue }
    
    $bytes = [System.IO.File]::ReadAllBytes($f.FullName)
    if ($bytes.Length -eq 0) { continue }

    $text = ""
    # 1. 判断是否带有 UTF-8 BOM (EF BB BF)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xef -and $bytes[1] -eq 0xbb -and $bytes[2] -eq 0xbf) {
        # 剔除前3个字节，防止 BOM 污染合并后的文本
        $text = [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3)
    } else {
        # 2. 尝试用 UTF-8 无 BOM 解码
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        
        # 3. 核心修正：如果文本中出现了 UTF-8 无法解析的替换字符 (U+FFFD)，说明本质上是 GBK/GB2312
        if ($text.Contains([char]0xFFFD)) {
            $text = $gbk.GetString($bytes)
        }
    }
    
    $allContent.Add("`r`n`r`n// ==========================================`r`n// File: $($f.FullName)`r`n// ==========================================`r`n" + $text)
}

# 最终统一使用 UTF-8 BOM 格式输出，方便所有系统和 AI 识别
[System.IO.File]::WriteAllText("$PWD\$OutFile", [string]::Join('', $allContent), $utf8BOM)