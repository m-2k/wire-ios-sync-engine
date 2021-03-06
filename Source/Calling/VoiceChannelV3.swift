//
// Wire
// Copyright (C) 2016 Wire Swiss GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.
//

import Foundation

public class VoiceChannelV3 : NSObject, VoiceChannel {

    public var callCenter: WireCallCenterV3? {
        return self.conversation?.managedObjectContext?.zm_callCenter
    }
    
    /// The date and time of current call start
    public var callStartDate: Date? {
        return self.callCenter?.establishedDate
    }
    
    weak public var conversation: ZMConversation?
    
    /// Voice channel participants. May be a subset of conversation participants.
    public var participants: NSOrderedSet {
        guard let callCenter = self.callCenter,
              let conversationId = conversation?.remoteIdentifier,
              let context = conversation?.managedObjectContext
        else { return NSOrderedSet() }
        
        let userIds = callCenter.callParticipants(conversationId: conversationId)
        let users = userIds.flatMap{ ZMUser(remoteID: $0, createIfNeeded: false, in:context) }
        return NSOrderedSet(array: users)
    }
    
    public required init(conversation: ZMConversation) {
        self.conversation = conversation
        super.init()
    }

    public func state(forParticipant participant: ZMUser) -> CallParticipantState {
        guard let conv = self.conversation,
            let convID = conv.remoteIdentifier,
            let userID = participant.remoteIdentifier,
            let callCenter = self.callCenter
        else { return .unconnected }
        
        if participant.isSelfUser {
            return callCenter.callState(conversationId: convID).callParticipantState
        } else {
            return callCenter.state(forUser: userID, in: convID)
        }
    }
    
    public var state: CallState {
        if let conversation = conversation, let remoteIdentifier = conversation.remoteIdentifier, let callCenter = self.callCenter {
            return callCenter.callState(conversationId: remoteIdentifier)
        } else {
            return .none
        }
    }
    
    public var isVideoCall: Bool {
        guard let remoteIdentifier = conversation?.remoteIdentifier else { return false }
        
        return self.callCenter?.isVideoCall(conversationId: remoteIdentifier) ?? false
    }
    
    public var isConstantBitRateAudioActive: Bool {
        return self.callCenter?.isConstantBitRateAudioActive ?? false
    }
    
    public var initiator : ZMUser? {
        guard let context = conversation?.managedObjectContext,
              let convId = conversation?.remoteIdentifier,
              let userId = self.callCenter?.initiatorForCall(conversationId: convId)
        else {
            return nil
        }
        return ZMUser.fetch(withRemoteIdentifier: userId, in: context)
    }
    
    public func toggleVideo(active: Bool) throws {
        guard let remoteIdentifier = conversation?.remoteIdentifier else { throw VoiceChannelV2Error.videoNotActiveError() }
        
        self.callCenter?.toogleVideo(conversationID: remoteIdentifier, active: active)
    }
    
    public func setVideoCaptureDevice(device: CaptureDevice) throws {
        guard let conversationId = conversation?.remoteIdentifier else { throw VoiceChannelV2Error.switchToVideoNotAllowedError() }
        
        self.callCenter?.setVideoCaptureDevice(device, for: conversationId)
    }
    
}

extension VoiceChannelV3 : CallActions {
    
    public func continueByDecreasingConversationSecurity(userSession: ZMUserSession) {
        guard let conversation = conversation else { return }
        conversation.makeNotSecure()
    }
    
    public func leaveAndKeepDegradedConversationSecurity(userSession: ZMUserSession) {
        guard let conversation = conversation else { return }
        userSession.syncManagedObjectContext.performGroupedBlock {
            let conversationId = conversation.objectID
            if let syncConversation = (try? userSession.syncManagedObjectContext.existingObject(with: conversationId)) as? ZMConversation {
                userSession.callingStrategy.dropPendingCallMessages(for: syncConversation)
            }
        }
        leave(userSession: userSession)
    }
    
    public func join(video: Bool, userSession: ZMUserSession) -> Bool {
        if userSession.callNotificationStyle == .callKit, #available(iOS 10.0, *) {
            userSession.callKitDelegate.requestJoinCall(in: conversation!, video: video)
            return true
        } else {
            return join(video: video)
        }
    }
    
    public func leave(userSession: ZMUserSession) {
        if userSession.callNotificationStyle == .callKit, #available(iOS 10.0, *) {
            userSession.callKitDelegate.requestEndCall(in: conversation!)
        } else {
            return leave()
        }
    }
    
    public func ignore(userSession: ZMUserSession) {
        if userSession.callNotificationStyle == .callKit, #available(iOS 10.0, *) {
            userSession.callKitDelegate.requestEndCall(in: conversation!)
        } else {
            return ignore()
        }
    }
    
}

extension VoiceChannelV3 : CallActionsInternal {
    
    public func join(video: Bool) -> Bool {
        guard let conversation = conversation,
              let remoteIdentifier = conversation.remoteIdentifier
        else { return false }
        
        let isGroup = (conversation.conversationType == .group)
        var joined = false
        
        switch state {
        case .incoming(video: _, shouldRing: _, degraded: let degraded):
            if !degraded {
                joined = callCenter?.answerCall(conversationId: remoteIdentifier) ?? false
            }
        default:
            joined = self.callCenter?.startCall(conversationId: remoteIdentifier, video: video, isGroup: isGroup) ?? false
        }
        
        return joined
    }
    
    public func leave() {
        guard let conv = conversation,
              let remoteID = conv.remoteIdentifier
        else { return }
        
        let isGroup = (conv.conversationType == .group)
        self.callCenter?.closeCall(conversationId: remoteID, isGroup: isGroup)
    }
    
    public func ignore() {
        guard let conv = conversation,
              let remoteID = conv.remoteIdentifier
        else { return }
        
        self.callCenter?.rejectCall(conversationId: remoteID)
    }
    
}

extension VoiceChannelV3 : CallObservers {
    
    /// Add observer of voice channel state. Returns a token which needs to be retained as long as the observer should be active.
    public func addCallStateObserver(_ observer: WireCallCenterCallStateObserver) -> Any {
        return WireCallCenterV3.addCallStateObserver(observer: observer, for: conversation!, context: conversation!.managedObjectContext!)
    }
    
    /// Add observer of voice channel participants. Returns a token which needs to be retained as long as the observer should be active.
    public func addParticipantObserver(_ observer: VoiceChannelParticipantObserver) -> Any {
        return WireCallCenterV3.addVoiceChannelParticipantObserver(observer: observer, for: conversation!, context: conversation!.managedObjectContext!)
    }
    
    /// Add observer of voice gain. Returns a token which needs to be retained as long as the observer should be active.
    public func addVoiceGainObserver(_ observer: VoiceGainObserver) -> Any {
        return WireCallCenterV3.addVoiceGainObserver(observer: observer, for: conversation!, context: conversation!.managedObjectContext!)
    }
    
    /// Add observer of received video. Returns a token which needs to be retained as long as the observer should be active.
    public func addReceivedVideoObserver(_ observer: ReceivedVideoObserver) -> Any {
        return WireCallCenterV3.addReceivedVideoObserver(observer: observer, context: conversation!.managedObjectContext!)
    }
    
    /// Add observer of constant bit rate audio. Returns a token which needs to be retained as long as the observer should be active.
    public func addConstantBitRateObserver(_ observer: ConstantBitRateAudioObserver) -> Any {
        return WireCallCenterV3.addConstantBitRateObserver(observer: observer, context: conversation!.managedObjectContext!)
    }
    
    /// Add observer of the state of all voice channels. Returns a token which needs to be retained as long as the observer should be active.
    public class func addCallStateObserver(_ observer: WireCallCenterCallStateObserver, userSession: ZMUserSession) -> Any {
        return WireCallCenterV3.addCallStateObserver(observer: observer, context: userSession.managedObjectContext!)
    }
    
}

public extension CallState {
        
    var callParticipantState : CallParticipantState {
        switch self {
        case .unknown, .terminating, .incoming, .none, .establishedDataChannel:
            return .unconnected
        case .established:
            return .connected(muted: false, sendingVideo: false)
        case .outgoing, .answered:
            return .connecting
        }
    }
    
}

