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


@import WireTransport;
@import WireUtilities;
@import WireDataModel;

#include "ZMAuthenticationStatus.h"
#include "ZMCredentials+Internal.h"
#include "NSError+ZMUserSession.h"
#include "NSError+ZMUserSessionInternal.h"
#include "ZMUserSessionRegistrationNotification.h"
#include "ZMUserSessionAuthenticationNotification.h"

#import "ZMAuthenticationStatus_Internal.h"


static NSString *const TimerInfoOriginalCredentialsKey = @"credentials";
static NSString * const AuthenticationCenterDataChangeNotificationName = @"ZMAuthenticationStatusDataChangeNotificationName";
NSString * const RegisteredOnThisDeviceKey = @"ZMRegisteredOnThisDevice";
NSTimeInterval DebugAuthenticationFailureTimerOverride = 0;

static NSString* ZMLogTag ZM_UNUSED = @"Authentication";


@implementation ZMAuthenticationStatus

- (instancetype)initWithCookieStorage:(ZMPersistentCookieStorage *)cookieStorage;
{
    self = [super init];
    if(self) {
        self.cookieStorage = cookieStorage;
        self.isWaitingForAuthentication = !self.isAuthenticated;
    }
    return self;
}

- (void)dealloc
{
    [self starAuthenticationTimer];
}

- (ZMCredentials *)authenticationCredentials
{
    return self.internalAuthenticationCredentials;
}

- (NSString *)cookieLabel
{
    return self.cookieStorage.cookieLabel;
}

- (void)setCookieLabel:(NSString *)label
{
    self.cookieStorage.cookieLabel = label;
}

- (void)resetAuthenticationAndRegistrationStatus
{
    [self stopAuthenticationTimer];
    
    self.registrationPhoneNumberThatNeedsAValidationCode = nil;
    self.authenticationPhoneNumberThatNeedsAValidationCode = nil;

    self.internalAuthenticationCredentials = nil;
    self.registrationPhoneValidationCredentials = nil;
    self.registrationUser = nil;

    self.isWaitingForEmailVerification = NO;
    
    self.duplicateRegistrationEmail = NO;
    self.duplicateRegistrationPhoneNumber = NO;
}

- (void)setRegistrationUser:(ZMCompleteRegistrationUser *)registrationUser
{
    if(self.internalRegistrationUser != registrationUser) {
        self.internalRegistrationUser = registrationUser;
        if (self.internalRegistrationUser.emailAddress != nil) {
            [ZMPersistentCookieStorage setCookiesPolicy:NSHTTPCookieAcceptPolicyNever];
        }
        else {
            [ZMPersistentCookieStorage setCookiesPolicy:NSHTTPCookieAcceptPolicyAlways];
        }
        [[NSNotificationCenter defaultCenter] postNotificationName:AuthenticationCenterDataChangeNotificationName object:self];
    }
}

- (ZMCompleteRegistrationUser *)registrationUser
{
    return self.internalRegistrationUser;
}

- (void)setAuthenticationCredentials:(ZMCredentials *)credentials
{
    if(credentials != self.internalAuthenticationCredentials) {
        self.internalAuthenticationCredentials = credentials;
        [ZMPersistentCookieStorage setCookiesPolicy:NSHTTPCookieAcceptPolicyAlways];
        [[NSNotificationCenter defaultCenter] postNotificationName:AuthenticationCenterDataChangeNotificationName object:self];
    }
}

- (void)addAuthenticationCenterObserver:(id<ZMAuthenticationStatusObserver>)observer;
{
    ZM_ALLOW_MISSING_SELECTOR
    ([[NSNotificationCenter defaultCenter] addObserver:observer selector:@selector(didChangeAuthenticationData) name:AuthenticationCenterDataChangeNotificationName object:nil]);
}

- (void)removeAuthenticationCenterObserver:(id<ZMAuthenticationStatusObserver>)observer;
{
    [[NSNotificationCenter defaultCenter] removeObserver:observer];
}

- (ZMAuthenticationPhase)currentPhase
{
    if(self.isAuthenticated) {
        return ZMAuthenticationPhaseAuthenticated;
    }
    if(self.isWaitingForEmailVerification) {
        return ZMAuthenticationPhaseWaitingForEmailVerification;
    }
    if(self.registrationUser.emailAddress != nil) {
        return ZMAuthenticationPhaseRegisterWithEmail;
    }
    if(self.registrationUser.phoneVerificationCode != nil || self.registrationUser.invitationCode != nil) {
        return ZMAuthenticationPhaseRegisterWithPhone;
    }
    if(self.internalAuthenticationCredentials.credentialWithEmail && self.isWaitingForAuthentication) {
        return ZMAuthenticationPhaseAuthenticateWithEmail;
    }
    if(self.internalAuthenticationCredentials.credentialWithPhone && self.isWaitingForAuthentication) {
        return ZMAuthenticationPhaseAuthenticateWithPhone;
    }
    if(self.registrationPhoneNumberThatNeedsAValidationCode != nil) {
        return ZMAuthenticationPhaseRequestPhoneVerificationCodeForRegistration;
    }
    if(self.authenticationPhoneNumberThatNeedsAValidationCode != nil) {
        return ZMAuthenticationPhaseRequestPhoneVerificationCodeForAuthentication;
    }
    if(self.registrationPhoneValidationCredentials != nil) {
        return ZMAuthenticationPhaseVerifyPhoneForRegistration;
    }
    return ZMAuthenticationPhaseUnauthenticated;
}

- (BOOL)needsCredentialsToAuthenticate
{
    return !self.isAuthenticated && self.authenticationCredentials == nil;
}

- (BOOL)isAuthenticated
{
    return self.hasCookie;
}

- (BOOL)hasCookie;
{
    NSData *cookie = [self.cookieStorage authenticationCookieData];
    return cookie != nil;
}

- (void)starAuthenticationTimer
{
    [self.authenticationTimer cancel];
    self.authenticationTimer = nil;
    self.authenticationTimer = [ZMTimer timerWithTarget:self];
    self.authenticationTimer.userInfo = @{ TimerInfoOriginalCredentialsKey : self.authenticationCredentials };
    [self.authenticationTimer fireAfterTimeInterval:(DebugAuthenticationFailureTimerOverride > 0 ?: 60 )];
}

- (void)stopAuthenticationTimer
{
    [self.authenticationTimer cancel];
    self.authenticationTimer = nil;
}

- (void)timerDidFire:(ZMTimer *)timer
{
    [self.moc performGroupedBlock:^{
        [self didTimeoutAuthenticationForCredentials:timer.userInfo[TimerInfoOriginalCredentialsKey]];
    }];
}

- (void)prepareForAuthenticationWithCredentials:(ZMCredentials *)credentials
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    [self setRegisteredOnThisDevice:NO];
    BOOL wasDuplicated = self.duplicateRegistrationPhoneNumber;
    [self resetAuthenticationAndRegistrationStatus];
    if(wasDuplicated && credentials.credentialWithPhone) {
        self.duplicateRegistrationPhoneNumber = YES;
    }
    self.authenticationCredentials = credentials;
    self.isWaitingForAuthentication = YES;
    [self starAuthenticationTimer];
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)prepareForRegistrationOfUser:(ZMCompleteRegistrationUser *)user
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    self.cookieStorage.authenticationCookieData = nil;
    self.isWaitingForAuthentication = YES;
    [self resetAuthenticationAndRegistrationStatus];
    self.registrationUser = user;
}

- (void)prepareForRequestingPhoneVerificationCodeForRegistration:(NSString *)phone
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    [self resetAuthenticationAndRegistrationStatus];
    [ZMPhoneNumberValidator validateValue:&phone error:nil];
    self.registrationPhoneNumberThatNeedsAValidationCode = phone;
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)prepareForRequestingPhoneVerificationCodeForAuthentication:(NSString *)phone;
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    [self resetAuthenticationAndRegistrationStatus];
    [ZMPhoneNumberValidator validateValue:&phone error:nil];
    self.authenticationPhoneNumberThatNeedsAValidationCode = phone;
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)prepareForRegistrationPhoneVerificationWithCredentials:(ZMPhoneCredentials *)phoneCredentials
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    // if it was duplicated phone, do authentication instead
    BOOL wasDuplicated = self.duplicateRegistrationPhoneNumber;
    [self resetAuthenticationAndRegistrationStatus];

    self.duplicateRegistrationPhoneNumber = wasDuplicated;
    if(wasDuplicated) {
        self.authenticationCredentials = phoneCredentials;
    }
    else {
        self.registrationPhoneValidationCredentials = phoneCredentials;
    }
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didFailRequestForPhoneRegistrationCode:(NSError *)error
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    if(error.code == ZMUserSessionPhoneNumberIsAlreadyRegistered) {
        self.duplicateRegistrationPhoneNumber = YES;
        self.authenticationPhoneNumberThatNeedsAValidationCode = self.registrationPhoneNumberThatNeedsAValidationCode;
        self.registrationPhoneNumberThatNeedsAValidationCode = nil;
        ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
        return;
    }
    
    [self resetAuthenticationAndRegistrationStatus];
    [ZMUserSessionRegistrationNotification notifyPhoneNumberVerificationCodeRequestDidFail:error];
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didCompleteRegistrationSuccessfully
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    self.completedRegistration = YES;
    
    if (self.currentPhase == ZMAuthenticationPhaseRegisterWithEmail) {
        ZMCredentials *credentials = [ZMEmailCredentials credentialsWithEmail:self.registrationUser.emailAddress password:self.registrationUser.password];
        //we need to set credentials first cause that will trigger notification and check for current state but we need to know that we are going from email registration to login attempts
        self.authenticationCredentials = credentials;
        self.registrationUser = nil;
        [ZMUserSessionRegistrationNotification notifyEmailVerificationDidSucceed];
    } else if (self.currentPhase == ZMAuthenticationPhaseAuthenticated) {
        [self authenticationSucceed];
    }
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didFailRegistrationWithDuplicatedEmail {
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    self.duplicateRegistrationEmail = YES;
    ZMCredentials *credentials = [ZMEmailCredentials credentialsWithEmail:self.registrationUser.emailAddress password:self.registrationUser.password];
    self.registrationUser = nil;
    self.authenticationCredentials = credentials;
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didFailRegistrationForOtherReasons:(NSError *)error;
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    [self resetAuthenticationAndRegistrationStatus];
    [ZMUserSessionRegistrationNotification notifyRegistrationDidFail:error];
}

- (void)didTimeoutAuthenticationForCredentials:(ZMCredentials *)credentials
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    if((self.currentPhase == ZMAuthenticationPhaseAuthenticateWithEmail || self.currentPhase == ZMAuthenticationPhaseAuthenticateWithPhone)
       && self.authenticationCredentials == credentials)
    {
        self.authenticationCredentials = nil;
        [ZMUserSessionAuthenticationNotification notifyAuthenticationDidFail:[NSError userSessionErrorWithErrorCode:ZMUserSessionNetworkError userInfo:nil]];
    }
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didCompletePhoneVerificationSuccessfully
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    [self resetAuthenticationAndRegistrationStatus];
    [ZMUserSessionRegistrationNotification notifyPhoneNumberVerificationDidSucceed];
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didFailPhoneVerificationForRegistration:(NSError *)error
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    [self resetAuthenticationAndRegistrationStatus];
    [ZMUserSessionRegistrationNotification notifyPhoneNumberVerificationDidFail:error];
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)authenticationSucceed
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    if (self.isWaitingForAuthentication) {
        self.isWaitingForAuthentication = NO;
    }
    [ZMUserSessionAuthenticationNotification notifyAuthenticationDidSucceed];
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didFailAuthenticationWithPhone:(BOOL)invalidCredentials
{
    ZMLogDebug(@"%@ invalid credentials: %d", NSStringFromSelector(_cmd), invalidCredentials);
    BOOL isDuplicated = self.duplicateRegistrationPhoneNumber;
    [self resetAuthenticationAndRegistrationStatus];
    
    if(isDuplicated) {
        NSError *error = [NSError userSessionErrorWithErrorCode:ZMUserSessionPhoneNumberIsAlreadyRegistered userInfo:nil];
        
        [ZMUserSessionRegistrationNotification notifyRegistrationDidFail:error];
    }
    else {
        NSError *error = [NSError userSessionErrorWithErrorCode:(invalidCredentials ? ZMUserSessionInvalidCredentials : ZMUserSessionUnkownError) userInfo:nil];

        [ZMUserSessionAuthenticationNotification notifyAuthenticationDidFail:error];
    }
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didFailAuthenticationWithEmail:(BOOL)invalidCredentials
{
    ZMLogDebug(@"%@ invalid credentials: %d", NSStringFromSelector(_cmd), invalidCredentials);
    if(self.duplicateRegistrationEmail) {
        [ZMUserSessionRegistrationNotification notifyRegistrationDidFail:[NSError userSessionErrorWithErrorCode:ZMUserSessionEmailIsAlreadyRegistered userInfo:@{}]];
    }
    else {
        NSError *error = [NSError userSessionErrorWithErrorCode:(invalidCredentials ? ZMUserSessionInvalidCredentials : ZMUserSessionUnkownError) userInfo:nil];
        [ZMUserSessionAuthenticationNotification notifyAuthenticationDidFail:error];
    }
    [self resetAuthenticationAndRegistrationStatus];
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didFailAuthenticationWithEmailBecausePendingValidation
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    self.isWaitingForEmailVerification = YES;
    NSError *error = [NSError userSessionErrorWithErrorCode:ZMUserSessionAccountIsPendingActivation userInfo:nil];
    [ZMUserSessionAuthenticationNotification notifyAuthenticationDidFail:error];
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)cancelWaitingForEmailVerification
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    [self resetAuthenticationAndRegistrationStatus];
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didCompleteRequestForPhoneRegistrationCodeSuccessfully;
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    self.registrationPhoneNumberThatNeedsAValidationCode = nil;
    [ZMUserSessionRegistrationNotification notifyPhoneNumberVerificationCodeRequestDidSucceed];
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)setAuthenticationCookieData:(NSData *)data;
{
    ZMLogDebug(@"Setting cookie data: %@", data != nil ? @"Nil" : @"Not nil");
    self.cookieStorage.authenticationCookieData = data;
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didCompleteRequestForAuthenticationCodeSuccessfully
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    [ZMUserSessionAuthenticationNotification notifyLoginCodeRequestDidSucceed];
    self.authenticationPhoneNumberThatNeedsAValidationCode = nil;
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

- (void)didFailRequestForAuthenticationCode:(NSError *)error;
{
    ZMLogDebug(@"%@", NSStringFromSelector(_cmd));
    self.authenticationPhoneNumberThatNeedsAValidationCode = nil;
    [ZMUserSessionAuthenticationNotification notifyLoginCodeRequestDidFail:error];
    ZMLogDebug(@"current phase: %lu", (unsigned long)self.currentPhase);
}

@end


@implementation ZMAuthenticationStatus (CredentialProvider)

- (void)credentialsMayBeCleared
{
    if (self.currentPhase == ZMAuthenticationPhaseAuthenticated) {
        [self resetAuthenticationAndRegistrationStatus];
    }
}

- (ZMEmailCredentials *)emailCredentials
{
    if (self.authenticationCredentials.credentialWithEmail) {
        return [ZMEmailCredentials credentialsWithEmail:self.authenticationCredentials.email
                                               password:self.authenticationCredentials.password];
    }
    return nil;
}

@end

static NSString * const CookieLabelKey = @"ZMCookieLabel";

@implementation NSManagedObjectContext (Registration)

- (void)setRegisteredOnThisDevice:(BOOL)registeredOnThisDevice
{
    assert(self.zm_isSyncContext);
    [self setPersistentStoreMetadata:@(registeredOnThisDevice) forKey:RegisteredOnThisDeviceKey];
    NSManagedObjectContext *uiContext = self.zm_userInterfaceContext;
    [uiContext performGroupedBlock:^{
        [uiContext setPersistentStoreMetadata:@(registeredOnThisDevice) forKey:RegisteredOnThisDeviceKey];
    }];
}

- (BOOL)isRegisteredOnThisDevice
{
    return ((NSNumber *)[self persistentStoreMetadataForKey:RegisteredOnThisDeviceKey]).boolValue;
}

- (NSString *)legacyCookieLabel
{
    NSString *label = [self persistentStoreMetadataForKey:CookieLabelKey];
    return label;
}

@end

