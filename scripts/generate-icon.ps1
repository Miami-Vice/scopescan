# Generates the 1024x1024 app icon.
#
# Xcode 14+ accepts a single-size app icon, so one PNG is all we need. Committed
# output means CI never has to run this; re-run only when the design changes.

Add-Type -AssemblyName System.Drawing

$out = Join-Path $PSScriptRoot '..\App\Resources\Assets.xcassets\AppIcon.appiconset\AppIcon-1024.png'
$out = [System.IO.Path]::GetFullPath($out)

$size = 1024
$bitmap = New-Object System.Drawing.Bitmap($size, $size)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias

# Deep navy field
$graphics.Clear([System.Drawing.Color]::FromArgb(255, 8, 18, 30))

$center = $size / 2
$accent = [System.Drawing.Color]::FromArgb(255, 46, 199, 186)

# Concentric range rings, fading outward
$radii = @(150, 250, 350, 450)
$alphas = @(255, 170, 110, 60)
for ($i = 0; $i -lt $radii.Count; $i++) {
    $r = $radii[$i]
    $color = [System.Drawing.Color]::FromArgb($alphas[$i], $accent)
    $pen = New-Object System.Drawing.Pen($color, 18)
    $graphics.DrawEllipse($pen, $center - $r, $center - $r, $r * 2, $r * 2)
    $pen.Dispose()
}

# Sweep wedge
$sweep = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(70, $accent))
$graphics.FillPie($sweep, $center - 450, $center - 450, 900, 900, -60, 60)
$sweep.Dispose()

# Center dot
$dot = New-Object System.Drawing.SolidBrush($accent)
$graphics.FillEllipse($dot, $center - 42, $center - 42, 84, 84)
$dot.Dispose()

$graphics.Dispose()
$bitmap.Save($out, [System.Drawing.Imaging.ImageFormat]::Png)
$bitmap.Dispose()

Write-Host "Wrote $out"
