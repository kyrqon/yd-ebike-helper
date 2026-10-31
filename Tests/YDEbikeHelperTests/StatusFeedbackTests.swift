import Foundation
import XCTest
@testable import YDEbikeHelper

final class StatusFeedbackTests: XCTestCase {
    func testPeriodicVehicleFieldNeverBecomesAnOperationResult() {
        for value: UInt8 in [0xE7, 0xEF] {
            var payload = [UInt8](repeating: 0xFF, count: 171)
            payload[35] = value // Frame offset 39, previously misread as ACK.
            let packet = frame(type: 0x2A, payload: payload)
            XCTAssertEqual(YDEbikeProtocol.vehicleStatusFrameType(from: packet), 0x2A)
            XCTAssertNil(YDEbikeProtocol.shortReportedState(from: packet))
        }
    }

    func testShortStatusSupportsObservedPaddingAndInvalidSentinel() throws {
        let unset = try YDEbikeProtocol.parseHex("59 44 29 08 00 FC FF FF FF FF FF FF 27 4B 4A")
        XCTAssertEqual(YDEbikeProtocol.shortReportedState(from: unset), 0)
        XCTAssertEqual(YDEbikeProtocol.shortReportedState(from: frame(type: 0x29, payload: [0x55, 0xFE])), 2)
        XCTAssertNil(YDEbikeProtocol.shortReportedState(from: frame(type: 0x29, payload: [0x55, 0xFF])))
        XCTAssertNil(YDEbikeProtocol.shortReportedState(from: frame(type: 0x29, payload: [0x55])))
        var brokenHeader = unset
        brokenHeader[0] = 0
        XCTAssertNil(YDEbikeProtocol.shortReportedState(from: brokenHeader))
    }

    func testUnsolicitedOrWrongStateDoesNotShowSuccess() {
        var feedback = OperationFeedback()
        XCTAssertNil(feedback.recordState(1))
        feedback.begin(label: "解除动力锁定", expectedValue: 1)
        XCTAssertNil(feedback.recordWriteConfirmation())
        XCTAssertNil(feedback.recordState(0))
        XCTAssertNil(feedback.recordState(3))
        XCTAssertNotNil(feedback.pendingID)
    }

    func testMatchingStateIsShownOnlyOnceAfterWriteConfirmation() {
        var feedback = OperationFeedback()
        feedback.begin(label: "解除动力锁定", expectedValue: 1)
        XCTAssertNil(feedback.recordWriteConfirmation())
        let notice = feedback.recordState(1)
        XCTAssertEqual(notice?.title, "车辆状态已确认")
        XCTAssertTrue(notice?.message.contains("解除动力锁定") == true)
        XCTAssertNil(feedback.recordState(1))
        XCTAssertNil(feedback.recordWriteConfirmation())
    }

    func testEarlyStateWaitsForWriteAndLatestStateWins() {
        var feedback = OperationFeedback()
        feedback.begin(label: "解除动力锁定", expectedValue: 1)
        XCTAssertNil(feedback.recordState(1))
        XCTAssertNil(feedback.recordState(0))
        XCTAssertNil(feedback.recordWriteConfirmation())
        XCTAssertNotNil(feedback.recordState(1))
        feedback.begin(label: "恢复动力锁定", expectedValue: 0)
        XCTAssertNil(feedback.recordState(0))
        XCTAssertNotNil(feedback.recordWriteConfirmation())
    }

    func testTimeoutAndDisconnectCannotProduceAFalseSuccess() throws {
        var feedback = OperationFeedback()
        feedback.begin(label: "解除动力锁定", expectedValue: 1)
        let id = try XCTUnwrap(feedback.pendingID)
        XCTAssertNil(feedback.recordWriteConfirmation())
        let notice = feedback.timeout(id: id)
        XCTAssertEqual(notice?.title, "指令已发送")
        XCTAssertTrue(notice?.message.contains("暂未收到") == true)
        XCTAssertNil(feedback.recordState(1))
        feedback.begin(label: "恢复动力锁定", expectedValue: 0)
        XCTAssertNil(feedback.timeout(id: id)) // An old timer cannot end a new operation.
        feedback.reset()
        XCTAssertNil(feedback.recordState(0))
        XCTAssertNil(feedback.recordWriteConfirmation())
    }

    func testPeriodicSamplingNeverDropsAuthOrShortStatusAndKeepsFirstSample() {
        var sampler = PeriodicStatusLogSampler(interval: 15)
        let start = Date(timeIntervalSince1970: 100)
        XCTAssertTrue(sampler.accept(frameType: 0x2A, now: start).shouldLog)
        XCTAssertTrue(sampler.accept(frameType: 0x2B, now: start).shouldLog)
        for tick in 1..<15 {
            XCTAssertFalse(sampler.accept(frameType: 0x2A, now: start.addingTimeInterval(Double(tick))).shouldLog)
            XCTAssertTrue(sampler.accept(frameType: 0x29, now: start).shouldLog)
            XCTAssertTrue(sampler.accept(frameType: nil, now: start).shouldLog)
        }
        let decision = sampler.accept(frameType: 0x2A, now: start.addingTimeInterval(15))
        XCTAssertTrue(decision.shouldLog)
        XCTAssertEqual(decision.suppressed, 14)
    }

    func testSuppressedTelemetryIsCountedBeforeReset() {
        var sampler = PeriodicStatusLogSampler()
        let start = Date(timeIntervalSince1970: 100)
        _ = sampler.accept(frameType: 0x2A, now: start)
        _ = sampler.accept(frameType: 0x2A, now: start.addingTimeInterval(1))
        _ = sampler.accept(frameType: 0x2B, now: start)
        _ = sampler.accept(frameType: 0x2B, now: start.addingTimeInterval(1))
        XCTAssertEqual(sampler.flush(), 2)
        XCTAssertEqual(sampler.flush(), 0)
        XCTAssertTrue(sampler.accept(frameType: 0x2A, now: start).shouldLog)
    }

    private func frame(type: UInt8, payload: [UInt8]) -> Data {
        var bytes: [UInt8] = [0x59, 0x44, type, UInt8(payload.count)] + payload
        bytes.append(bytes[2...].reduce(UInt8(0)) { $0 &+ $1 })
        bytes += [0x4B, 0x4A]
        return Data(bytes)
    }
}
