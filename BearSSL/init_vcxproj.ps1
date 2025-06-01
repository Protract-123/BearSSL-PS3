# Define variables
$repoUrl = "https://www.bearssl.org/git/BearSSL"
$tempDir = "temp_clone"

# Clone repo into temporary directory
git clone $repoUrl $tempDir

# Define the folder names you want to extract
$foldersToMove = @("src", "inc")

# Move selected folders to the current directory
foreach ($folder in $foldersToMove) {
    $sourcePath = Join-Path -Path $tempDir -ChildPath $folder
    if (Test-Path $sourcePath) {
        Move-Item -Path $sourcePath -Destination "." -Force
    } else {
        Write-Warning "Folder '$folder' not found in cloned repo."
    }
}

# Remove the temporary clone directory (including its .git folder)
Remove-Item -Path $tempDir -Recurse -Force

# Set the root directory (change this path if needed)
$RootDir = "."  # You can set this to "." to use the current directory

# Get all files from subdirectories (excluding root-level files)
$Files = Get-ChildItem -Path $RootDir -Recurse -File | Where-Object { $_.DirectoryName -ne (Get-Item $RootDir).FullName }

foreach ($File in $Files) {
    $TargetPath = Join-Path -Path $RootDir -ChildPath $File.Name

    # If a file with the same name exists, skip copying
    if (-not (Test-Path $TargetPath)) {
        # Copy the file if it does not already exist
        Copy-Item -Path $File.FullName -Destination $TargetPath
    } else {
        # Inform that the file is skipped
        Write-Host "Skipped (duplicate): $($File.Name)"
    }
}

$CFiles = Get-ChildItem -Path $RootDir -File -Filter "*.c"
$HFiles = Get-ChildItem -Path $RootDir -File -Filter "*.h"

# Path to the file
$filePath = "BearSSL.vcxproj"

# Read all lines into an array
$lines = Get-Content $filePath
# Insert the new line before line 64 (array is 0-indexed, so position 63)

# Add .c files to vcxproj
$CFiles | ForEach-Object {  
    $include_line = "    <ClCompile Include=`"$($_.Name)`" />"
    $lines = $lines[0..63] + $include_line + $lines[63..($lines.Count - 1)]
}

Set-Content -Path $filePath -Value $lines

# Calculate the index for insertion: 5th from the end
$insertIndex = $lines.Count - 5

$itemGroupLine = "  <ItemGroup>"

# Insert new lines before the 5th-last line
$lines = $lines[0..($insertIndex - 1)] + $itemGroupLine + $lines[$insertIndex..($lines.Count - 1)]


$HFiles | ForEach-Object {  
    $insertIndex = $lines.Count - 5
    $include_line = "    <ClInclude Include=`"$($_.Name)`" />"
    $lines = $lines[0..($insertIndex - 1)] + $include_line + $lines[$insertIndex..($lines.Count - 1)]
}

$itemGroupTerminatorLine = "  </ItemGroup>"
$insertIndex = $lines.Count - 5
# Insert new lines before the 5th-last line
$lines = $lines[0..($insertIndex - 1)] + $itemGroupTerminatorLine + $lines[$insertIndex..($lines.Count - 1)]

Set-Content -Path $filePath -Value $lines