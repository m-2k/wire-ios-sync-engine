//
// Wire
// Copyright (C) 2017 Wire Swiss GmbH
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

private let zmLog = ZMSLog(tag: "Push")

extension ZMUserSession {
    
    // MARK: - Foreground Actions
    
    public func handleConnectionRequestCategoryNotification(_ note : ZMStoredLocalNotification) {
        guard let sender = ZMUser.fetch(withRemoteIdentifier: note.senderUUID, in: managedObjectContext) else { return }
        
        if note.actionIdentifier == ZMConnectAcceptAction {
            sender.accept()
            managedObjectContext.saveOrRollback()
        }
        
        open(sender.connection?.conversation, at: nil)
    }
    
    public func handleCallCategoryNotification(_ note : ZMStoredLocalNotification) {
        guard let actionIdentifier = note.actionIdentifier, actionIdentifier == ZMCallAcceptAction,
              let callState = note.conversation.voiceChannel?.state
        else {
            open(note.conversation, at: nil)
            return
        }
        
        if case let .incoming(video: video, shouldRing: _, degraded: _) = callState, callCenter?.activeCallConversations(in: self).count == 0 {
            _ = note.conversation.voiceChannel?.join(video: video, userSession: self)
        }
        
        open(note.conversation, at: nil)
    }
    
    public func handleDefaultCategoryNotification(_ note: ZMStoredLocalNotification) {
        open(note.conversation, at: nil)
    }
    
    func open(_ conversation: ZMConversation?, at message : ZMMessage?) {
        guard let strongDelegate = requestToOpenViewDelegate else { return }
            
        if conversation == nil {
            strongDelegate.showConversationList(for: self)
        }
        else if message == nil {
            strongDelegate.userSession(self, show: conversation)
        } else {
            strongDelegate.userSession(self, show: message, in: conversation)
        }
    }
    
    // MARK: - Background Actions
    
    public func ignoreCall(with notification: UILocalNotification, completionHandler: @escaping () -> Void) {
        let activity = BackgroundActivityFactory.sharedInstance().backgroundActivity(withName: "IgnoreCall Action Handler")
        let conversation = notification.conversation(in: managedObjectContext)
        
        managedObjectContext.perform { 
            conversation?.voiceChannel?.ignore(userSession: self)
            activity?.end()
            completionHandler()
        }
    }
    
    public  func muteConversation(with notification: UILocalNotification, completionHandler: @escaping () -> Void) {
        let activity = BackgroundActivityFactory.sharedInstance().backgroundActivity(withName: "Mute Conversation Action Handler")
        let conversation = notification.conversation(in: managedObjectContext)
        
        managedObjectContext.perform { 
            conversation?.isSilenced = true
            self.managedObjectContext.saveOrRollback()
            activity?.end()
            completionHandler()
        }
    }
    
    public  func reply(with notification: UILocalNotification, message: String, completionHandler: @escaping () -> Void) {
        guard !message.isEmpty,
              let conversation = notification.conversation(in: managedObjectContext)
        else {
            completionHandler()
            return
        }
        
        let activity = BackgroundActivityFactory.sharedInstance().backgroundActivity(withName: "DirectReply Action Handler")
        
        operationStatus.startBackgroundTask { [weak self] (result) in
            guard let `self` = self else { return }
            
            self.messageReplyObserver = nil
            self.syncManagedObjectContext.performGroupedBlock {
                if result == .failed {
                    zmLog.warn("failed to reply via push notification action")
                    let conversationOnSyncContext = notification.conversation(in: self.syncManagedObjectContext)
                    self.localNotificationDispatcher.didFailToSendMessage(in: conversationOnSyncContext!)
                }
                activity?.end()
                completionHandler()
            }
        }
                
        enqueueChanges {
            guard let message = conversation.appendMessage(withText: message) else { return /* failure */ }
            self.messageReplyObserver = ManagedObjectContextChangeObserver(context: self.managedObjectContext, callback: { [weak self] in
                self?.updateBackgroundTask(with: message)
            })
        }
        
        
    }
    
    public func likeMessage(with notification: UILocalNotification, completionHandler: @escaping () -> Void) {
        guard let conversation = notification.conversation(in: managedObjectContext),
              let message = notification.message(in: conversation, in: managedObjectContext)
        else {
            completionHandler()
            return
        }
        
        let activity = BackgroundActivityFactory.sharedInstance().backgroundActivity(withName: "Like Message Activity")
        
        operationStatus.startBackgroundTask { [weak self] (result) in
            guard let `self` =  self else { return }
            
            self.likeMesssageObserver = nil
            if result == .failed {
                zmLog.warn("failed to like message via push notification action")
            }
            activity?.end()
            completionHandler()
        }
        
        enqueueChanges {
            guard let reaction = ZMMessage.addReaction(.like, toMessage: message) else { return }
            self.likeMesssageObserver = ManagedObjectContextChangeObserver(context: self.managedObjectContext, callback: { [weak self] in
                self?.updateBackgroundTask(with: reaction)
            })
        }
        
        
    }
    
    func updateBackgroundTask(with message : ZMConversationMessage) {
        switch message.deliveryState {
        case .sent, .delivered:
            operationStatus.finishBackgroundTask(withTaskResult: .finished)
        case .failedToSend:
            operationStatus.finishBackgroundTask(withTaskResult: .failed)
        default:
            break
        }
    }

}
