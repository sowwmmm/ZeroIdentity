import argparse
import exiftool
import json
import os
import sys


def normalize_exiftool_path(exiftool_path):
    if not exiftool_path:
        return None

    if os.path.isdir(exiftool_path):
        candidate = os.path.join(exiftool_path, "exiftool.exe" if os.name == "nt" else "exiftool")
        if os.path.isfile(candidate):
            return candidate

    if os.path.isfile(exiftool_path):
        return exiftool_path

    if os.name == "nt":
        candidate = f"{exiftool_path}.exe"
        if os.path.isfile(candidate):
            return candidate

    return exiftool_path


class ExtractMetadata:
    def __init__(self, file_path, exiftool_path=None):
        self.file_path = file_path
        self.exiftool_path = normalize_exiftool_path(exiftool_path)

    def extract_metadata(self):
        with exiftool.ExifToolHelper(executable=self.exiftool_path) as et:
            return et.get_metadata(self.file_path)

    def change_metadata(self, key, value):
        with exiftool.ExifToolHelper(executable=self.exiftool_path) as et:
            et.set_tags({key: value})

    def find_sensitive_metadata(self, metadata):
        sensitive_keys = {
            # =========================
            # GPS / LOCATION
            # =========================
            "GPSLatitude",
            "GPSLongitude",
            "GPSLatitudeRef",
            "GPSLongitudeRef",
            "GPSAltitude",
            "GPSAltitudeRef",
            "GPSPosition",
            "GPSMapDatum",
            "GPSDestLatitude",
            "GPSDestLongitude",
            "GPSDateStamp",
            "GPSTimeStamp",
            "GPSImgDirection",
            "GPSImgDirectionRef",
            "GPSProcessingMethod",
            "GPSAreaInformation",
            "GPSDifferential",
            "GPSHPositioningError",
            "Country",
            "CountryCode",
            "State",
            "Province",
            "City",
            "Sub-location",
            "Location",
            "RegionName",

            # =========================
            # DEVICE / CAMERA
            # =========================
            "Make",
            "Model",
            "CameraModelName",
            "UniqueCameraModel",
            "DeviceManufacturer",
            "DeviceModelName",
            "SerialNumber",
            "InternalSerialNumber",
            "LensModel",
            "LensInfo",
            "LensSerialNumber",
            "OwnerName",
            "BodySerialNumber",
            "FirmwareVersion",
            "Software",
            "CreatorTool",
            "HostComputer",
            "CameraOwnerName",
            "ImageUniqueID",

            # =========================
            # USER / AUTHOR IDENTITY
            # =========================
            "Author",
            "Creator",
            "Artist",
            "By-line",
            "Copyright",
            "Publisher",
            "Producer",
            "Company",
            "Manager",
            "Operator",
            "Contributor",
            "LastModifiedBy",
            "Application",
            "CreatorAddress",
            "CreatorCity",
            "CreatorRegion",
            "CreatorPostalCode",
            "CreatorCountry",
            "CreatorWorkEmail",
            "CreatorWorkURL",
            "CreatorWorkTelephone",
            "UserComment",
            "Comment",
            "Description",
            "Instructions",

            # =========================
            # TIME / TIMESTAMPS
            # =========================
            "DateTime",
            "DateTimeOriginal",
            "DateTimeDigitized",
            "CreateDate",
            "ModifyDate",
            "MetadataDate",
            "TrackCreateDate",
            "TrackModifyDate",
            "MediaCreateDate",
            "MediaModifyDate",
            "ContentCreateDate",
            "ContentModifyDate",
            "FileModifyDate",
            "FileAccessDate",
            "FileCreateDate",
            "FileInodeChangeDate",
            "CreationDate",
            "ProfileDateTime",

            # =========================
            # IMAGE / CAMERA SETTINGS
            # =========================
            "ExposureTime",
            "ShutterSpeed",
            "FNumber",
            "Aperture",
            "MaxApertureValue",
            "ISOSpeedRatings",
            "ISO",
            "FocalLength",
            "Flash",
            "FlashMode",
            "WhiteBalance",
            "ExposureProgram",
            "ExposureMode",
            "ExposureCompensation",
            "MeteringMode",
            "LightSource",
            "SceneCaptureType",
            "DigitalZoomRatio",
            "Contrast",
            "Saturation",
            "Sharpness",
            "BrightnessValue",
            "GainControl",
            "SubjectDistance",
            "SubjectArea",
            "ColorSpace",
            "SensingMethod",

            # =========================
            # FILESYSTEM / OS
            # =========================
            "FileName",
            "Directory",
            "FilePath",
            "FileSize",
            "FilePermissions",
            "MIMEType",
            "FileType",
            "FileTypeExtension",
            "EncodingProcess",
            "BitsPerSample",
            "Compression",
            "ImageWidth",
            "ImageHeight",
            "Megapixels",
            "Orientation",
            "XResolution",
            "YResolution",
            "ResolutionUnit",

            # =========================
            # NETWORK / SYSTEM
            # =========================
            "MACAddress",
            "IPAddress",
            "Hostname",
            "ComputerName",
            "SSID",
            "BSSID",
            "ProfileName",
            "RouterMAC",
            "MachineID",

            # =========================
            # PDF / DOCUMENT
            # =========================
            "Title",
            "Subject",
            "Keywords",
            "Template",
            "RevisionNumber",
            "TotalEditTime",
            "Pages",
            "Language",
            "DocumentID",
            "InstanceID",
            "History",
            "Version",
            "Hyperlinks",
            "EmbeddedFiles",
            "HiddenSlides",
            "TrackedChanges",
            "Notes",
            "PageCount",

            # =========================
            # THUMBNAILS / PREVIEWS
            # =========================
            "ThumbnailImage",
            "PreviewImage",
            "JpgFromRaw",
            "OtherImage",
            "MPImage",
            "CoverArt",

            # =========================
            # VIDEO / AUDIO
            # =========================
            "HandlerDescription",
            "CompressorName",
            "EncodingSoftware",
            "MediaDataOffset",
            "AudioChannels",
            "AudioSampleRate",
            "Duration",
            "AvgBitrate",
            "VideoFrameRate",
            "Encoder",
            "MajorBrand",
            "CompatibleBrands",

            # =========================
            # SOCIAL / EDITING SOFTWARE
            # =========================
            "XMPToolkit",
            "Adobe",
            "Photoshop",
            "GIMP",
            "Canva",
            "CapCut",
            "Snapseed",
            "PicsArt",
            "Lightroom",
            "Premiere",
            "AfterEffects",

            # =========================
            # FORENSICALLY IMPORTANT
            # =========================
            "ImageUniqueID",
            "DocumentAncestors",
            "OriginalDocumentID",
            "OriginalTransmissionReference",
            "DigitalSourceType",
            "SourceFile",
            "DerivedFrom",
            "PreservedFileName",
            "PreservedPath",
        }

        entries = []
        if isinstance(metadata, dict):
            entries.append(metadata)
        elif isinstance(metadata, list):
            for item in metadata:
                if isinstance(item, dict):
                    entries.append(item)

        found_sensitive = {}
        for entry in entries:
            for key, value in entry.items():
            
                # Remove namespace prefix
                clean_key = key.split(":")[-1]
        
                if clean_key in sensitive_keys:
                    found_sensitive[key] = value
        
        return found_sensitive


def print_metadata(metadata, as_json=False):
    if as_json:
        print(json.dumps(metadata, indent=4))
        return

    if not metadata:
        print("No metadata found.")
        return

    if isinstance(metadata, list):
        for item in metadata:
            if isinstance(item, dict):
                for key, value in item.items():
                    print(f"{key}: {value}")
            else:
                print(item)
    elif isinstance(metadata, dict):
        for key, value in metadata.items():
            print(f"{key}: {value}")
    else:
        print(metadata)


def delete_sensitive_metadata(file_path, keys_to_delete, exiftool_path=None):
    keys_to_delete = set(keys_to_delete)
    if not keys_to_delete:
        return

    delete_args = []
    for key in keys_to_delete:
        delete_args.append(f"-{key}=".encode("utf-8"))

    with exiftool.ExifToolHelper(executable=normalize_exiftool_path(exiftool_path)) as et:
        et.execute(*delete_args, file_path.encode("utf-8"))


def parse_args():
    parser = argparse.ArgumentParser(description="Extract or update metadata for a file")
    parser.add_argument("file", help="Path to the target file")
    parser.add_argument("--json", action="store_true", help="Print metadata as JSON")
    parser.add_argument("--quiet", action="store_true", help="Only print results or errors")
    parser.add_argument("--set", nargs=2, metavar=("KEY", "VALUE"), help="Set a metadata tag")
    parser.add_argument("--delete-sensitive", action="store_true", help="Delete sensitive metadata tags")
    parser.add_argument("--show-after", action="store_true", help="Show metadata after deleting sensitive tags")
    return parser.parse_args()


def main():
    args = parse_args()
    extractor = ExtractMetadata(args.file)

    try:
        if args.set:
            key, value = args.set
            extractor.change_metadata(key, value)
            if not args.quiet:
                print(f"Updated metadata: {key} = {value}")

        metadata = extractor.extract_metadata()
        if not args.quiet:
            print("Metadata before deletion:" if args.delete_sensitive else "Metadata:")
        print_metadata(metadata, as_json=args.json)

        if args.delete_sensitive:
            sensitive = extractor.find_sensitive_metadata(metadata)
            if sensitive:
                if not args.quiet:
                    print("\nDeleting sensitive metadata:\n")
                delete_sensitive_metadata(args.file, sensitive.keys())
                if not args.quiet:
                    print("Sensitive metadata deleted successfully.")
                    print("\nMetadata after deletion:")
                metadata_after_deletion = extractor.extract_metadata()
                print_metadata(metadata_after_deletion, as_json=args.json)
            elif not args.quiet:
                print("\nNo sensitive metadata found to delete.")
    except FileNotFoundError:
        print(f"File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
