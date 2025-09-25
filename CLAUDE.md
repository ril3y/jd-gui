# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

JD-GUI is a standalone Java Swing desktop application for displaying Java source code decompiled from `.class` files. It serves as a graphical frontend to the JD-Core decompiler library with a plugin-based SPI architecture.

## Build System & Commands

**Build Tool**: Gradle 5.2.1 with Java 1.8 target compatibility

```bash
# Build the entire project
./gradlew build

# Run tests
./gradlew test

# Generate IDE project files
./gradlew idea      # IntelliJ IDEA
./gradlew eclipse   # Eclipse

# Run the application
./gradlew run
# Or from built JAR:
java -jar build/libs/jd-gui-1.6.6.jar
```

## Project Architecture

**Multi-module Gradle project** with three main modules:

### 1. api module (`api/`)
- Core API interfaces and SPI contracts
- Main entry: `org.jd.gui.api.API` - Central API for plugin interactions
- Contains feature interfaces, model definitions, and SPI definitions

### 2. app module (`app/`)
- Main application logic, GUI controllers, and Swing views
- Key packages:
  - `org.jd.gui.controller` - MVC controllers
  - `org.jd.gui.view` - Swing UI components
  - `org.jd.gui.service` - Application services
  - `org.jd.gui.model` - Data models and configuration
- Main class: `org.jd.gui.App`

### 3. services module (`services/`)
- Implementation of decompilation services and plugins
- Container support (JAR, EAR), file type handlers, decompilers
- Uses ANTLR grammar parsing with auto-generated code in `src-generated/`

## Key Dependencies

- **JD-Core 1.1.3**: Core decompilation engine
- **RSyntaxTextArea 3.0.4**: Syntax highlighting
- **ASM 7.1**: Java bytecode manipulation
- **ANTLR 4.5**: Grammar parsing
- **Launch4j**: Windows executable wrapper
- **ProGuard 6.1.0**: Code minification

## Development Notes

### Plugin Architecture
- Uses Java SPI pattern with META-INF/services
- Factory pattern for different file types and containers
- Extensible through custom decompilers and file handlers

### Testing
- Framework: JUnit 4.12
- Test location: `services/src/test/java/`
- Key tests: `DescriptorMatcherTest`, `ClassFilePageTest`, `JavaFilePageTest`

### Distribution
- Cross-platform builds: Windows (.exe), macOS (.app), Linux (.deb/.rpm)
- Single executable JAR with all dependencies bundled
- ProGuard minification creates `jd-gui-x.y.z-min.jar`

### Configuration
- Application preferences: `jd-gui.cfg`
- ANTLR generates sources automatically to `src-generated/antlr/java/`
- Single instance mode with IPC support