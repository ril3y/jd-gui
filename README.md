# JD-GUI Enhanced

JD-GUI, a standalone graphical utility that displays Java sources from CLASS files with enhanced security analysis capabilities.

![](https://raw.githubusercontent.com/java-decompiler/jd-gui/master/src/website/img/jd-gui.png)

- Java Decompiler projects home page: [http://java-decompiler.github.io](http://java-decompiler.github.io)
- Original JD-GUI source code: [https://github.com/java-decompiler/jd-gui](https://github.com/java-decompiler/jd-gui)

## Description
JD-GUI is a standalone graphical utility that displays Java source codes of
".class" files. You can browse the reconstructed source code with the JD-GUI
for instant access to methods and fields.

### Enhanced Features
- **SHA-256 Hash Generation**: Generate cryptographic hashes for .class files
- **Security Analysis Integration**: Built-in integration with security analysis services
- **Multi-file Processing**: Bulk operations on selected files with Ctrl+click support
- **Enhanced Build System**: Modern Gradle wrapper with Windows executable generation

## How to build JD-GUI ?

### Prerequisites
- **Java 8 or higher** (Java 8 recommended for compatibility)
- **Git** with submodule support

### Build Instructions
```bash
# Clone the repository
> git clone https://github.com/java-decompiler/jd-gui.git
> cd jd-gui

# Initialize and clone the JD-Core submodule (REQUIRED)
> git submodule init
> git submodule update

# Build the project
> ./gradlew build
```

### Windows Executable Build
To build a Windows executable (.exe):
```bash
> ./gradlew buildExe
```
This generates: `build/launch4j/jd-gui.exe`

### IDE Project Generation
Generate IDE project files for development:
```bash
# Generate IntelliJ IDEA project files
> ./gradlew idea

# Generate Eclipse project files
> ./gradlew eclipse
```

### Build Outputs
The build process generates:
- `build/libs/jd-gui-x.y.z.jar` - Main application JAR
- `build/libs/jd-gui-x.y.z-min.jar` - Minified JAR
- `build/launch4j/jd-gui.exe` - Windows executable
- `build/distributions/jd-gui-windows-x.y.z.zip` - Windows distribution
- `build/distributions/jd-gui-osx-x.y.z.tar` - macOS distribution
- `build/distributions/jd-gui-x.y.z.deb` - Debian package
- `build/distributions/jd-gui-x.y.z.rpm` - RPM package

## How to launch JD-GUI ?
- Double-click on _"jd-gui-x.y.z.jar"_
- Double-click on _"jd-gui.exe"_ application from Windows
- Double-click on _"JD-GUI"_ application from Mac OSX
- Execute _"java -jar jd-gui-x.y.z.jar"_ or _"java -classpath jd-gui-x.y.z.jar org.jd.gui.App"_

## How to use JD-GUI ?
- Open a file with menu "File > Open File..."
- Open recent files with menu "File > Recent Files"
- Drag and drop files from your file explorer

## How to extend JD-GUI ?
```
> ./gradlew idea 
```
generate Idea Intellij project
```
> ./gradlew eclipse
```
generate Eclipse project
```
> java -classpath jd-gui-x.y.z.jar;myextension1.jar;myextension2.jar org.jd.gui.App
```
launch JD-GUI with your extensions

## How to uninstall JD-GUI ?
- Java: Delete "jd-gui-x.y.z.jar" and "jd-gui.cfg".
- Mac OSX: Drag and drop "JD-GUI" application into the trash.
- Windows: Delete "jd-gui.exe" and "jd-gui.cfg".

## License
Released under the [GNU GPL v3](LICENSE).

## Donations
Did JD-GUI help you to solve a critical situation? Do you use JD-Eclipse daily? What about making a donation?

[![paypal](https://raw.githubusercontent.com/java-decompiler/jd-gui/master/src/website/img/btn_donate_euro.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=C88ZMVZ78RF22) [![paypal](https://raw.githubusercontent.com/java-decompiler/jd-gui/master/src/website/img/btn_donate_usd.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=CRMXT4Y4QLQGU)
