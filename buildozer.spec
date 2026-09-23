[app]

# App title and package name
title = PoC Hunter
package.name = pochunter
package.domain = com.felix.security

# Version
version = 1.0.0

# App requirements: Python modules and system libraries
requirements = python3,kivy,requests,urllib3

# Permissions for Android
android.permissions = INTERNET

# Features
android.features = android.hardware.internet

# Orientation: portrait for mobile-friendly UI
orientation = portrait

# Arch targets (arm64-v8a for most modern phones, armeabi-v7a for older devices)
android.archs = arm64-v8a

# Android API level (31 is reasonable for modern devices)
android.api = 31
android.minapi = 21
android.ndk = 25b

# Pre-built wheel directory (optional, for faster builds)
# android.accept_sdk_license = True

# Gradle build configuration
android.gradle_dependencies =

# Icon and presplash (optional - would need .png files)
# icon.filename = %(source.dir)s/data/icon.png
# presplash.filename = %(source.dir)s/data/presplash.png

# Java classes used for opening URLs
android.entrypoint = org.kivy.android.PythonActivity
p4a.bootstrap = sdl2

# Build-specific settings
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
source.exclude_exts = spec

# Build directory
build.dir = .buildozer
build.logger_level = 2

[buildozer]

# Log level (0 = error only, 1 = info, 2 = debug)
log_level = 2

# Display warnings
warn_on_root = 1
