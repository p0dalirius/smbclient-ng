# Function to create a file with specified content
function Create-File {
    param (
        [string]$Path,
        [string]$Content
    )
    New-Item -ItemType File -Path $Path -Force
    Set-Content -Path $Path -Value $Content
}

# Function to create a directory
function Create-Directory {
    param (
        [string]$Path
    )
    New-Item -ItemType Directory -Path $Path -Force
}

$baseDir = "C:\TestShare\"

# Create directories and files for testing

# Create base share directory
New-PSDrive -Name "TestShare" -PSProvider FileSystem -Root $baseDir -Persist

# Create a directory structure
Create-Directory -Path "$baseDir\Users\John\Documents"
Create-Directory -Path "$baseDir\Users\John\Documents\Projects"
Create-Directory -Path "$baseDir\Users\John\Documents\Projects\Project1"
Create-Directory -Path "$baseDir\Users\John\Documents\Projects\Project2"
Create-Directory -Path "$baseDir\Users\John\Pictures"
Create-Directory -Path "$baseDir\empty_folder"
Create-Directory -Path "$baseDir\restricted_folder"

# Create files with different use cases
Create-File -Path "$baseDir\Users\John\Documents\file.txt" -Content "This is a test file."
Create-File -Path "$baseDir\Users\John\Documents\large_file.raw" -Content ("a" * 1000000) # Large file
Create-File -Path "$baseDir\Users\John\Documents\Projects\Project1\project_file1.txt" -Content "Project1 File"
Create-File -Path "$baseDir\Users\John\Documents\Projects\Project2\project_file2.txt" -Content "Project2 File"
Create-File -Path "$baseDir\Users\John\Pictures\image.jpg" -Content "FakeImageContent"
Create-File -Path "$baseDir\Users\John\Documents\document.pdf" -Content "PDF content"
Create-File -Path "$baseDir\Users\John\Documents\report.docx" -Content "Report content"

# Create files in restricted folder
Create-File -Path "$baseDir\restricted_folder\protected_file.txt" -Content "Protected content"

# Set restricted folder permissions
$restrictedFolderPath = "$remotePath\restricted_folder"
icacls $restrictedFolderPath /deny "Everyone:(OI)(CI)(F)"
