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
import WireDataModel
import CoreData

@objc(ZMCallStateObserver)
public final class CallStateObserver : NSObject {
    
    static public let CallInProgressNotification = Notification.Name(rawValue: "ZMCallInProgressNotification")
    static public let CallInProgressKey = "callInProgress"
    
    fileprivate weak var userSession: ZMUserSession?
    fileprivate let localNotificationDispatcher : LocalNotificationDispatcher
    fileprivate let syncManagedObjectContext : NSManagedObjectContext
    fileprivate var callStateToken : Any? = nil
    fileprivate var missedCalltoken : Any? = nil
    fileprivate let systemMessageGenerator = CallSystemMessageGenerator()
    
    public init(localNotificationDispatcher : LocalNotificationDispatcher, userSession: ZMUserSession) {
        self.userSession = userSession
        self.localNotificationDispatcher = localNotificationDispatcher
        self.syncManagedObjectContext = userSession.syncManagedObjectContext
        
        super.init()
        
        self.callStateToken = WireCallCenterV3.addCallStateObserver(observer: self, context: userSession.managedObjectContext)
        self.missedCalltoken = WireCallCenterV3.addMissedCallObserver(observer: self, context: userSession.managedObjectContext)
    }
    
    fileprivate var callInProgress : Bool = false {
        didSet {
            if callInProgress != oldValue {
                syncManagedObjectContext.performGroupedBlock {
                    NotificationInContext(name: CallStateObserver.CallInProgressNotification,
                                          context: self.syncManagedObjectContext.notificationContext,
                                          userInfo: [ CallStateObserver.CallInProgressKey : self.callInProgress ]).post()
                }
            }
        }
    }
    
}

extension CallStateObserver : WireCallCenterCallStateObserver, WireCallCenterMissedCallObserver  {
    
    public func callCenterDidChange(callState: CallState, conversation: ZMConversation, user: ZMUser?, timeStamp: Date?) {
        
        let userId = user?.remoteIdentifier
        let conversationId = conversation.remoteIdentifier
        
        syncManagedObjectContext.performGroupedBlock {
            guard
                let userId = userId,
                let conversationId = conversationId,
                let conversation = ZMConversation(remoteID: conversationId, createIfNeeded: false, in: self.syncManagedObjectContext),
                let user = ZMUser(remoteID: userId, createIfNeeded: false, in: self.syncManagedObjectContext)
            else {
                return
            }
            
            let uiManagedObjectContext = self.syncManagedObjectContext.zm_userInterface
            uiManagedObjectContext?.performGroupedBlock {
                if let noneIdleCallCount = uiManagedObjectContext?.zm_callCenter?.nonIdleCalls.count {
                    self.callInProgress = noneIdleCallCount > 0
                }
            }
            
            if (self.userSession?.callNotificationStyle ?? .callKit) == .pushNotifications {
                self.localNotificationDispatcher.process(callState: callState, in: conversation, sender: user)
            }
            
            self.updateConversationListIndicator(convObjectID: conversation.objectID, callState: callState)
            
            if let systemMessage = self.systemMessageGenerator.appendSystemMessageIfNeeded(callState: callState, conversation: conversation, user: user, timeStamp: timeStamp) {
                switch (systemMessage.systemMessageType, callState, conversation.conversationType) {
                case (.missedCall, .terminating(reason: .canceled), _ ):
                    // the caller canceled the call
                    fallthrough
                case (.missedCall, .terminating(reason: .normal), .group):
                    // group calls we didn't join, end with reason .normal. We should still insert a missed call in this case.
                    // since the systemMessageGenerator keeps track whether we joined or not, we can use it to decide whether we should show a missed call APNS
                    self.localNotificationDispatcher.processMissedCall(in: conversation, sender: user)
                default:
                    break
                }
            }
            
            if let timeStamp = timeStamp {
                conversation.updateLastModifiedDateIfNeeded(timeStamp)
            }
            self.syncManagedObjectContext.enqueueDelayedSave()
        }
    }
    
    public func updateConversationListIndicator(convObjectID: NSManagedObjectID, callState: CallState){
        // We need to switch to the uiContext here because we are making changes that need to be present on the UI when the change notification fires
        guard let uiMOC = self.syncManagedObjectContext.zm_userInterface else { return }
        uiMOC.performGroupedBlock {
            guard let uiConv = (try? uiMOC.existingObject(with: convObjectID)) as? ZMConversation else { return }
            
            switch callState {
            case .incoming(video: _, shouldRing: let shouldRing, degraded: _):
                uiConv.isIgnoringCall = uiConv.isSilenced || !shouldRing
                uiConv.isCallDeviceActive = false
            case .terminating, .none:
                uiConv.isCallDeviceActive = false
                uiConv.isIgnoringCall = false
            case .outgoing, .answered, .established:
                uiConv.isCallDeviceActive = true
            case .unknown, .establishedDataChannel:
                break
            }
            
            if uiMOC.zm_hasChanges {
                NotificationDispatcher.notifyNonCoreDataChanges(objectID: convObjectID,
                                                                changedKeys: [ZMConversationListIndicatorKey],
                                                                uiContext: uiMOC)
            }
        }
    }
    
    public func callCenterMissedCall(conversation: ZMConversation, user: ZMUser, timestamp: Date, video: Bool) {
        let userId = user.remoteIdentifier
        let conversationId = conversation.remoteIdentifier
        
        syncManagedObjectContext.performGroupedBlock {
            guard
                let userId = userId,
                let conversationId = conversationId,
                let conversation = ZMConversation(remoteID: conversationId, createIfNeeded: false, in: self.syncManagedObjectContext),
                let user = ZMUser(remoteID: userId, createIfNeeded: false, in: self.syncManagedObjectContext)
                else {
                    return
            }
            
            if (self.userSession?.callNotificationStyle ?? .callKit) == .pushNotifications {
                self.localNotificationDispatcher.processMissedCall(in: conversation, sender: user)
            }
            
            conversation.appendMissedCallMessage(fromUser: user, at: timestamp)
            self.syncManagedObjectContext.enqueueDelayedSave()
        }
    }

}
