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

extension ZMCredentials {
    var isInvalid: Bool {
        let noEmail = email?.isEmpty ?? true
        let noPassword = password?.isEmpty ?? true
        let noNumber = phoneNumber?.isEmpty ?? true
        let noVerificationCode = phoneNumberVerificationCode?.isEmpty ?? true
        return (noEmail || noPassword) && (noNumber || noVerificationCode)
    }
}

extension UnauthenticatedSession {
    
    var isLoggedIn: Bool {
        return authenticationStatus.currentPhase == .authenticated
    }
    
    /// Attempt to log in with the given credentials
    @objc(loginWithCredentials:)
    public func login(with credentials: ZMCredentials) {
        moc.performGroupedBlock {
            if self.isLoggedIn {
                ZMUserSessionAuthenticationNotification.notifyAuthenticationDidSucceed()
            } else if credentials.isInvalid {
                ZMUserSessionAuthenticationNotification.notifyAuthenticationDidFail(NSError.userSessionErrorWith(.needsCredentials, userInfo: nil))
            } else {
                self.authenticationStatus.prepareForLogin(with: credentials)
            }
            RequestAvailableNotification.notifyNewRequestsAvailable(nil)
        }
    }
    
}