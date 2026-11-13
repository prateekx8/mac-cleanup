// photo_sense: the Photo sorter's eyes (docs/PHOTO-SORT.md).
//
// Reads file paths on stdin, one per line, and writes one JSON object per line on stdout:
// date taken, camera, size, GPS, and what Apple's on-device Vision sees (labels, faces, lines of text,
// a quality score, "utility" for screenshots and receipts, and a fingerprint for finding similar photos).
// It only reads files. Nothing leaves the Mac. Build: swiftc -O photo_sense.swift -o photo_sense
//
//   --no-vision   metadata only (faster)
import AVFoundation
import Foundation
import ImageIO
import Vision

setvbuf(stdout, nil, _IOLBF, 0)
let useVision = !CommandLine.arguments.contains("--no-vision")
let videoExts: Set<String> = ["mov", "mp4", "m4v", "3gp", "avi", "mts"]
let maxSide = 1024  // Vision looks at a thumbnail: much faster, same labels

func emit(_ obj: [String: Any]) {
    if let d = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]),
       let s = String(data: d, encoding: .utf8) {
        print(s)
    }
}

func gpsValue(_ gps: [String: Any]) -> [Double]? {
    guard var lat = gps[kCGImagePropertyGPSLatitude as String] as? Double,
          var lon = gps[kCGImagePropertyGPSLongitude as String] as? Double else { return nil }
    if (gps[kCGImagePropertyGPSLatitudeRef as String] as? String) == "S" { lat = -lat }
    if (gps[kCGImagePropertyGPSLongitudeRef as String] as? String) == "W" { lon = -lon }
    return (lat == 0 && lon == 0) ? nil : [lat, lon]
}

final class Box: @unchecked Sendable { var d: [String: Any] = [:] }

func video(_ url: URL, _ out: inout [String: Any]) {
    let asset = AVURLAsset(url: url)
    out["kind"] = "video"
    let box = Box()
    let sem = DispatchSemaphore(value: 0)
    Task {
        if let d = try? await asset.load(.duration) { box.d["duration"] = CMTimeGetSeconds(d) }
        if let item = try? await asset.load(.creationDate), let date = try? await item.load(.dateValue) {
            box.d["created"] = ISO8601DateFormatter().string(from: date)
        }
        if let meta = try? await asset.load(.metadata) {
            for item in meta {
                guard let id = item.identifier, let s = try? await item.load(.stringValue) else { continue }
                if id == .quickTimeMetadataLocationISO6709 { box.d["iso6709"] = s }
                if id == .quickTimeMetadataMake { box.d["make"] = s }
                if id == .quickTimeMetadataModel { box.d["model"] = s }
            }
        }
        sem.signal()
    }
    if sem.wait(timeout: .now() + 20) == .timedOut { out["error"] = "the video took too long to read" }
    out.merge(box.d) { a, _ in a }
}

func image(_ url: URL, _ out: inout [String: Any]) {
    guard let src = CGImageSourceCreateWithURL(url as CFURL, nil) else {
        out["error"] = "not an image macOS can read"
        return
    }
    out["kind"] = "image"
    let props = CGImageSourceCopyPropertiesAtIndex(src, 0, nil) as? [String: Any] ?? [:]
    let exif = props[kCGImagePropertyExifDictionary as String] as? [String: Any] ?? [:]
    let tiff = props[kCGImagePropertyTIFFDictionary as String] as? [String: Any] ?? [:]
    out["w"] = props[kCGImagePropertyPixelWidth as String] ?? 0
    out["h"] = props[kCGImagePropertyPixelHeight as String] ?? 0
    if let v = exif[kCGImagePropertyExifDateTimeOriginal as String] { out["taken"] = v }
    if let v = exif[kCGImagePropertyExifOffsetTimeOriginal as String] { out["offset"] = v }
    if let v = tiff[kCGImagePropertyTIFFMake as String] { out["make"] = v }
    if let v = tiff[kCGImagePropertyTIFFModel as String] { out["model"] = v }
    if let v = tiff[kCGImagePropertyTIFFSoftware as String] { out["software"] = v }
    if let g = props[kCGImagePropertyGPSDictionary as String] as? [String: Any], let p = gpsValue(g) { out["gps"] = p }
    if !useVision { return }
    let opts: [CFString: Any] = [kCGImageSourceCreateThumbnailFromImageAlways: true,
                                 kCGImageSourceCreateThumbnailWithTransform: true,
                                 kCGImageSourceThumbnailMaxPixelSize: maxSide]
    guard let cg = CGImageSourceCreateThumbnailAtIndex(src, 0, opts as CFDictionary) else {
        out["error"] = "couldn't decode the picture"
        return
    }
    let handler = VNImageRequestHandler(cgImage: cg, options: [:])
    let classify = VNClassifyImageRequest()
    let faces = VNDetectFaceRectanglesRequest()
    let textReq = VNRecognizeTextRequest()
    textReq.recognitionLevel = .fast
    textReq.usesLanguageCorrection = false
    let print_ = VNGenerateImageFeaturePrintRequest()
    var requests: [VNRequest] = [classify, faces, textReq, print_]
    var aesthetics: VNRequest? = nil
    if #available(macOS 15.0, *) {
        let a = VNCalculateImageAestheticsScoresRequest()
        aesthetics = a
        requests.append(a)
    }
    do { try handler.perform(requests) } catch {
        out["error"] = "Vision: \(error.localizedDescription)"
        return
    }
    out["labels"] = (classify.results ?? []).filter { $0.confidence >= 0.3 }.prefix(6)
        .map { [$0.identifier, (Double($0.confidence) * 100).rounded() / 100] }
    out["faces"] = faces.results?.count ?? 0
    out["text"] = textReq.results?.count ?? 0
    if #available(macOS 15.0, *), let a = (aesthetics as? VNCalculateImageAestheticsScoresRequest)?.results?.first {
        out["quality"] = (Double(a.overallScore) * 100).rounded() / 100
        out["utility"] = a.isUtility
    }
    if let fp = print_.results?.first, fp.elementType == .float {
        out["fp"] = fp.data.base64EncodedString()
    }
}

while let line = readLine(strippingNewline: true) {
    if line.isEmpty { continue }
    autoreleasepool {
        let url = URL(fileURLWithPath: line)
        var out: [String: Any] = ["path": line]
        if videoExts.contains(url.pathExtension.lowercased()) {
            video(url, &out)
        } else {
            image(url, &out)
        }
        emit(out)
    }
}
