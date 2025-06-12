import os
import shutil
import subprocess
from pathlib import Path
import stat

def force_remove_readonly(func, path, excinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)

# --- Configuration ---
repo_url = "https://www.bearssl.org/git/BearSSL"
temp_dir = Path("temp_clone")
target_dir = Path("BearSSL")         # Where BearSSL.vcxproj is located
vcxproj_file = target_dir / "BearSSL.vcxproj"
root_dir = Path(__file__).parent     # The directory where this script resides

# --- Clone Repository ---
subprocess.run(["git", "clone", repo_url, str(temp_dir)], check=True)

# --- Move 'src' and 'inc' folders into target directory ---
for folder_name in ["src", "inc"]:
    source = temp_dir / folder_name
    if source.exists():
        shutil.move(str(source), target_dir)
    else:
        print(f"Warning: Folder '{folder_name}' not found in cloned repo.")

# --- Clean up ---
shutil.rmtree(temp_dir, ignore_errors=True)

# --- Copy non-root files from subdirectories into BearSSL dir if not duplicate ---
for file in target_dir.rglob("*.*"):
    if file.parent != target_dir and file.is_file():
        destination = target_dir / file.name
        if not destination.exists():
            shutil.copy(file, destination)
        else:
            print(f"Skipped (duplicate): {file.name}")

# --- Gather .c and .h files in BearSSL directory ---
c_files = list(target_dir.glob("*.c"))
h_files = list(target_dir.glob("*.h"))

# --- Edit BearSSL.vcxproj ---
with vcxproj_file.open("r", encoding="utf-8") as f:
    lines = f.readlines()

# Insert .c files before line 65 (index 64)
insert_index = 64
for c_file in c_files:
    lines.insert(insert_index, f'    <ClCompile Include="{c_file.name}" />\n')
    insert_index += 1

# Insert <ItemGroup> and .h files before 5th-last line
insert_index = len(lines) - 5
lines.insert(insert_index, "  <ItemGroup>\n")
insert_index += 1

for h_file in h_files:
    lines.insert(insert_index, f'    <ClInclude Include="{h_file.name}" />\n')
    insert_index += 1

lines.insert(insert_index, "  </ItemGroup>\n")

# Write changes
with vcxproj_file.open("w", encoding="utf-8") as f:
    f.writelines(lines)
    
if temp_dir.exists():
    shutil.rmtree(temp_dir, onerror=force_remove_readonly)
