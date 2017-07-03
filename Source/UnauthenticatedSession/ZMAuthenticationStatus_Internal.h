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


#import <WireSyncEngine/WireSyncEngine.h>

@interface ZMAuthenticationStatus () <ZMTimerClient>

@property (nonatomic) ZMPersistentCookieStorage *cookieStorage;
@property (nonatomic, copy) NSString *registrationPhoneNumberThatNeedsAValidationCode;
@property (nonatomic, copy) NSString *authenticationPhoneNumberThatNeedsAValidationCode;

@property (nonatomic) ZMCredentials *internalAuthenticationCredentials;
@property (nonatomic) ZMPhoneCredentials *registrationPhoneValidationCredentials;
@property (nonatomic) ZMCompleteRegistrationUser *internalRegistrationUser;

@property (nonatomic) BOOL isWaitingForEmailVerification;
@property (nonatomic) BOOL completedRegistration;

@property (nonatomic) BOOL duplicateRegistrationEmail;
@property (nonatomic) BOOL duplicateRegistrationPhoneNumber;

@property (nonatomic) BOOL isWaitingForAuthentication;

@property (nonatomic) NSManagedObjectContext *moc;
@property (nonatomic) BOOL canClearCredentials;

@property (nonatomic) ZMTimer *authenticationTimer;


- (void)resetAuthenticationAndRegistrationStatus;
- (void)setAuthenticationCredentials:(ZMCredentials *)credentials;

@end

