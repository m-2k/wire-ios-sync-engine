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


@import WireMockTransport;
@import WireMessageStrategy;

#import "MessagingTest.h"
#import <libkern/OSAtomic.h>
#import <CommonCrypto/CommonCrypto.h>

@import MobileCoreServices;
@import CoreData;
@import WireTransport;
@import WireMockTransport;
@import WireDataModel;

#import "ZMTimingTests.h"
#import "MockModelObjectContextFactory.h"

#import "ZMObjectStrategyDirectory.h"

#import "ZMUserTranscoder.h"
#import "ZMConversationTranscoder.h"
#import "ZMSelfStrategy.h"
#import "ZMConnectionTranscoder.h"
#import "ZMRegistrationTranscoder.h"
#import "ZMPhoneNumberVerificationTranscoder.h"
#import "ZMMissingUpdateEventsTranscoder.h"
#import "ZMLastUpdateEventIDTranscoder.h"
#import "ZMCallFlowRequestStrategy.h"
#import "ZMLoginTranscoder.h"
#import "ZMLoginCodeRequestTranscoder.h"
#import "ZMUserSession+Internal.h"
#import <WireSyncEngine/WireSyncEngine-Swift.h>
#import "WireSyncEngine_iOS_Tests-Swift.h"

static ZMReachability *sharedReachabilityMock = nil;

@interface MockTransportSession (Reachability)
@property (nonatomic, readonly) ZMReachability *reachability;
@end

@implementation MockTransportSession (Reachability)

- (ZMReachability *)reachability
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedReachabilityMock = OCMClassMock(ZMReachability.class);
        [[[(id)sharedReachabilityMock stub] andReturnValue:[NSNumber numberWithBool:YES]] mayBeReachable];
    });
    return sharedReachabilityMock;
}

@end

@interface MessagingTest () 

@property (nonatomic) NSManagedObjectContext *testMOC;
@property (nonatomic) NSManagedObjectContext *alternativeTestMOC;
@property (nonatomic) ManagedObjectContextDirectory *contextDirectory;

@property (nonatomic) NSString *groupIdentifier;
@property (nonatomic) NSUUID *userIdentifier;
@property (nonatomic) NSURL *sharedContainerURL;

@property (nonatomic) MockTransportSession *mockTransportSession;

@property (nonatomic) NSTimeInterval originalConversationLastReadTimestampTimerValue; // this will speed up the tests A LOT

@end




@implementation MessagingTest
@synthesize mockUserSession = _mockUserSession;

- (BOOL)shouldSlowTestTimers
{
    return [self.class isDebuggingTests] && !self.ignoreTestDebugFlagForTestTimers;
}

- (void)performPretendingUiMocIsSyncMoc:(void(^)(void))block;
{
    if(!block) {
        return;
    }
    [self.uiMOC resetContextType];
    [self.uiMOC markAsSyncContext];
    block();
    [self.uiMOC resetContextType];
    [self.uiMOC markAsUIContext];
}

- (BOOL)shouldUseRealKeychain;
{
    return NO;
}

- (BOOL)shouldUseInMemoryStore;
{
    return YES;
}

- (NSURL *)storeURL
{
    return self.accountDirectory.URLAppendingPersistentStoreLocation;
}

- (NSURL *)accountDirectory
{
    return [StorageStack accountFolderWithAccountIdentifier:self.userIdentifier applicationContainer:self.sharedContainerURL];
}

- (NSURL *)keyStoreURL
{
    return self.sharedContainerURL;
}

- (void)setUp;
{
    [super setUp];
    
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *bundleIdentifier = [NSBundle bundleForClass:self.class].bundleIdentifier;
    self.groupIdentifier = [@"group." stringByAppendingString:bundleIdentifier];
    self.userIdentifier = [NSUUID UUID];
    self.sharedContainerURL = [fm containerURLForSecurityApplicationGroupIdentifier:self.groupIdentifier];
    
    NSURL *otrFolder = [NSFileManager keyStoreURLForAccountInDirectory:self.accountDirectory createParentIfNeeded:NO];
    [fm removeItemAtURL:otrFolder error: nil];
    
    _application = [[ApplicationMock alloc] init];
    
    self.originalConversationLastReadTimestampTimerValue = ZMConversationDefaultLastReadTimestampSaveDelay;
    ZMConversationDefaultLastReadTimestampSaveDelay = 0.02;
    
    NSString *testName = NSStringFromSelector(self.invocation.selector);
    NSString *methodName = [NSString stringWithFormat:@"setup%@%@", [testName substringToIndex:1].capitalizedString, [testName substringFromIndex:1]];
    SEL selector = NSSelectorFromString(methodName);
    if ([self respondsToSelector:selector]) {
        ZM_SILENCE_CALL_TO_UNKNOWN_SELECTOR([self performSelector:selector]);
    }

    StorageStack.shared.createStorageAsInMemory = self.shouldUseInMemoryStore;

    [self resetState];
    
    if (self.shouldUseRealKeychain) {
        [ZMPersistentCookieStorage setDoNotPersistToKeychain:NO];
        
#if ! TARGET_IPHONE_SIMULATOR
        // On the Xcode Continuous Intergration server the tests run as a user whose username starts with an underscore.
        BOOL const runningOnIntegrationServer = [[[NSProcessInfo processInfo] environment][@"USER"] hasPrefix:@"_"];
        if (runningOnIntegrationServer) {
            [ZMPersistentCookieStorage setDoNotPersistToKeychain:YES];
        }
#endif
    } else {
        [ZMPersistentCookieStorage setDoNotPersistToKeychain:YES];
    }
    
    [self resetUIandSyncContextsAndResetPersistentStore:YES];
    
    ZMPersistentCookieStorage *cookieStorage = [[ZMPersistentCookieStorage alloc] init];
    [cookieStorage deleteKeychainItems];
    
    self.testMOC = [MockModelObjectContextFactory testContext];
    [self.testMOC addGroup:self.dispatchGroup];
    self.alternativeTestMOC = [MockModelObjectContextFactory alternativeMocForPSC:self.testMOC.persistentStoreCoordinator];
    [self.alternativeTestMOC addGroup:self.dispatchGroup];

    [self.searchMOC addGroup:self.dispatchGroup];
    self.mockTransportSession = [[MockTransportSession alloc] initWithDispatchGroup:self.dispatchGroup];
    Require([self waitForAllGroupsToBeEmptyWithTimeout:5]);
}

- (NSManagedObjectContext *)uiMOC
{
    return self.contextDirectory.uiContext;
}

- (NSManagedObjectContext *)syncMOC
{
    return self.contextDirectory.syncContext;
}

- (NSManagedObjectContext *)searchMOC
{
    return self.contextDirectory.searchContext;
}

- (void)tearDown;
{
    [(id)_mockUserSession stopMocking];
    _mockUserSession = nil;

    ZMConversationDefaultLastReadTimestampSaveDelay = self.originalConversationLastReadTimestampTimerValue;

    [self resetState];
    [MessagingTest deleteAllFilesInCache];
    [self removeFilesInSharedContainer];

    _application = nil;
    self.groupIdentifier = nil;
    self.sharedContainerURL = nil;

    [super tearDown];
    Require([self waitForAllGroupsToBeEmptyWithTimeout:5]);
}

- (void)tearDownUserInfoObjectsOfMOC:(NSManagedObjectContext *)moc
{
    NSMutableArray *keysToRemove = [NSMutableArray array];
    [moc.userInfo enumerateKeysAndObjectsUsingBlock:^(id  key, id  obj, BOOL * ZM_UNUSED stop) {
        if ([obj respondsToSelector:@selector(tearDown)]) {
            [obj tearDown];
            [keysToRemove addObject:key];
        }
    }];
    [moc.userInfo removeObjectsForKeys:keysToRemove];
}

- (void)removeFilesInSharedContainer
{
    for (NSURL *url in [NSFileManager.defaultManager contentsOfDirectoryAtURL:self.sharedContainerURL includingPropertiesForKeys:nil options:NSDirectoryEnumerationSkipsHiddenFiles error:nil]) {
        NSError *error = nil;
        [NSFileManager.defaultManager removeItemAtURL:url error:&error];
        if (error) {
            ZMLogError(@"Error cleaning up %@ in %@: %@", url, self.self.sharedContainerURL, error);
        }
    }
}

- (void)resetState
{
    [self tearDownUserInfoObjectsOfMOC:self.uiMOC];
    [self tearDownUserInfoObjectsOfMOC:self.testMOC];
    
    [self.syncMOC performGroupedBlock:^{
        [self tearDownUserInfoObjectsOfMOC:self.syncMOC];
        [self.syncMOC zm_tearDownCryptKeyStore];
        [self.syncMOC.userInfo removeAllObjects];
    }];

    WaitForAllGroupsToBeEmpty(0.5);
    
    // teardown all mmanagedObjectContexts
    [self cleanUpAndVerify];

    [self.mockTransportSession tearDown];
    self.mockTransportSession = nil;
    
    self.ignoreTestDebugFlagForTestTimers = NO;

    [StorageStack reset];
}

- (void)waitAndDeleteAllManagedObjectContexts;
{
    NSManagedObjectContext *refUiMOC = self.uiMOC;
    NSManagedObjectContext *refTestMOC = self.testMOC;
    NSManagedObjectContext *refAlternativeTestMOC = self.alternativeTestMOC;
    NSManagedObjectContext *refSearchMoc = self.searchMOC;
    NSManagedObjectContext *refSyncMoc = self.syncMOC;
    WaitForAllGroupsToBeEmpty(2);

    self.contextDirectory = nil;
    self.testMOC = nil;
    self.alternativeTestMOC = nil;
    
    [refUiMOC performBlockAndWait:^{
        // Do nothing.
    }];
    [refSyncMoc performBlockAndWait:^{
        
    }];
    [self.mockTransportSession.managedObjectContext performBlockAndWait:^{
        // Do nothing
    }];
    [refTestMOC performBlockAndWait:^{
        // Do nothing
    }];
    [refAlternativeTestMOC performBlockAndWait:^{
        // Do nothing
    }];
    [refSearchMoc performBlockAndWait:^{
        // Do nothing
    }];
}

- (void)cleanUpAndVerify {
    [self waitAndDeleteAllManagedObjectContexts];
    [self verifyMocksNow];
}

- (void)resetUIandSyncContextsAndResetPersistentStore:(BOOL)resetPersistentStore
{
    [self resetUIandSyncContextsAndResetPersistentStore:resetPersistentStore notificationContentHidden:NO];
}

- (void)resetUIandSyncContextsAndResetPersistentStore:(BOOL)resetPersistentStore notificationContentHidden:(BOOL)notificationContentVisible;
{
    [self tearDownUserInfoObjectsOfMOC:self.uiMOC];
    [self.syncMOC performGroupedBlockAndWait:^{
        [self tearDownUserInfoObjectsOfMOC:self.syncMOC];
    }];
    WaitForAllGroupsToBeEmpty(0.5);
    
    self.contextDirectory = nil;
    
    WaitForAllGroupsToBeEmpty(2);
    
    if (resetPersistentStore) {
        [StorageStack reset];
    }

    StorageStack.shared.createStorageAsInMemory = self.shouldUseInMemoryStore;

    [StorageStack.shared createManagedObjectContextDirectoryForAccountIdentifier:self.userIdentifier
                                                            applicationContainer:self.sharedContainerURL
                                                                   dispatchGroup:self.dispatchGroup
                                                        startedMigrationCallback:nil
                                                               completionHandler:^(ManagedObjectContextDirectory * _Nonnull directory) {
                                                                   self.contextDirectory = directory;
                                                               }];

    XCTAssert([self waitWithTimeout:0.5 verificationBlock:^BOOL{
        return nil != self.contextDirectory;
    }]);
    
    ImageAssetCache *imageAssetCache = [[ImageAssetCache alloc] initWithMBLimit:100 location:nil];
    FileAssetCache *fileAssetCache = [[FileAssetCache alloc] initWithLocation:nil];
    
    [self.uiMOC addGroup:self.dispatchGroup];
    self.uiMOC.userInfo[@"TestName"] = self.name;

    [self.syncMOC performGroupedBlockAndWait:^{
        self.syncMOC.userInfo[@"TestName"] = self.name;
        [self.syncMOC addGroup:self.dispatchGroup];
        [self.syncMOC saveOrRollback];
        
        [self.syncMOC setZm_userInterfaceContext:self.uiMOC];
        [self.syncMOC setPersistentStoreMetadata:@(notificationContentVisible) forKey:@"ZMShouldNotificationContentKey"];
        self.syncMOC.zm_imageAssetCache = imageAssetCache;
        self.syncMOC.zm_fileAssetCache = fileAssetCache;
    }];
    
    WaitForAllGroupsToBeEmpty(2);
    
    [self performPretendingUiMocIsSyncMoc:^{
        [self.uiMOC setupUserKeyStoreInAccountDirectory:self.accountDirectory applicationContainer:self.sharedContainerURL];
    }];
    
    [self.uiMOC saveOrRollback];
    WaitForAllGroupsToBeEmpty(2);
    
    
    [self.uiMOC setZm_syncContext:self.syncMOC];
    [self.uiMOC setPersistentStoreMetadata:@(notificationContentVisible) forKey:@"ZMShouldNotificationContentKey"];

    self.uiMOC.zm_imageAssetCache = imageAssetCache;
    self.uiMOC.zm_fileAssetCache = fileAssetCache;
}

- (id<ZMObjectStrategyDirectory>)createMockObjectStrategyDirectoryInMoc:(NSManagedObjectContext *)moc;
{
    id objectDirectory = [OCMockObject mockForProtocol:@protocol(ZMObjectStrategyDirectory)];
    
    id conversationTranscoder = [OCMockObject mockForClass:ZMConversationTranscoder.class];
    [self verifyMockLater:conversationTranscoder];
    id systemMessageEventConsumer = [OCMockObject mockForClass:SystemMessageEventsConsumer.class];
    [self verifyMockLater:systemMessageEventConsumer];
    id clientMessageTranscoder = [OCMockObject mockForClass:ClientMessageTranscoder.class];
    [self verifyMockLater:clientMessageTranscoder];
    id selfStrategy = [OCMockObject mockForClass:ZMSelfStrategy.class];
    [self verifyMockLater:selfStrategy];
    id missingUpdateEventsTranscoder = [OCMockObject mockForClass:ZMMissingUpdateEventsTranscoder.class];
    [self verifyMockLater:missingUpdateEventsTranscoder];
    id callFlowRequestStrategy = [OCMockObject mockForClass:ZMCallFlowRequestStrategy.class];
    [self verifyMockLater:callFlowRequestStrategy];
    
    [[[objectDirectory stub] andReturn:clientMessageTranscoder] clientMessageTranscoder];
    [[[objectDirectory stub] andReturn:selfStrategy] selfStrategy];
    [[[objectDirectory stub] andReturn:missingUpdateEventsTranscoder] missingUpdateEventsTranscoder];
    
    [[[objectDirectory stub] andReturn:moc] moc];
    [self verifyMockLater:objectDirectory];

    return objectDirectory;
}

- (ZMUserSession *)mockUserSession
{
    if (nil == _mockUserSession) {
        id mockUserSession = [OCMockObject niceMockForClass:[ZMUserSession class]];
        [[[mockUserSession stub] andReturn:self.uiMOC] managedObjectContext];
        [[[mockUserSession stub] andReturn:self.syncMOC] syncManagedObjectContext];
        [[[mockUserSession stub] andReturn:self.searchMOC] searchManagedObjectContext];
        [[[mockUserSession stub] andReturn:self.sharedContainerURL] sharedContainerURL];
        [(ZMUserSession *)[[mockUserSession stub] andReturn:self.mockTransportSession] transportSession];
        _mockUserSession = mockUserSession;
    }
    
    return _mockUserSession;
}

- (BOOL)waitWithTimeout:(NSTimeInterval)timeout forSaveOfContext:(NSManagedObjectContext *)moc untilBlock:(BOOL(^)(void))block;
{
    Require(moc != nil);
    Require(block != nil);
    
    timeout = [MessagingTest timeToUseForOriginalTime:timeout];
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    
    NSDate * const start = [NSDate date];
    NSNotificationCenter * const center = [NSNotificationCenter defaultCenter];
    id token = [center addObserverForName:NSManagedObjectContextDidSaveNotification object:moc queue:nil usingBlock:^(NSNotification *note) {
        NOT_USED(note);
        if (block()) {
            dispatch_semaphore_signal(sem);
        }
    }];
    
    BOOL success = NO;
    
    // We try to block the current thread as much as possible to not use too much CPU:
    NSDate * const stopDate = [NSDate dateWithTimeIntervalSinceNow:timeout];
    while ((! success) && (NSDate.timeIntervalSinceReferenceDate < stopDate.timeIntervalSinceReferenceDate)) {
        // Block this thread for a bit:
        NSTimeInterval const blockingTimeout = 0.01;
        success = (0 == dispatch_semaphore_wait(sem, dispatch_walltime(NULL, llround(blockingTimeout * NSEC_PER_SEC))));
        // Let anything on the main run loop run:
        [MessagingTest performRunLoopTick];
    }
    
    [center removeObserver:token];
    PrintTimeoutWarning(self, timeout, -[start timeIntervalSinceNow]);
    return success;
}


@end



@implementation MessagingTest (Asyncronous)

- (NSArray *)allManagedObjectContexts;
{
    NSMutableArray *result = [NSMutableArray array];
    if (self.uiMOC != nil) {
        [result addObject:self.uiMOC];
    }
    if (self.syncMOC != nil) {
        [result addObject:self.syncMOC];
    }
    if (self.testMOC != nil) {
        [result addObject:self.testMOC];
    }
    if (self.alternativeTestMOC != nil) {
        [result addObject:self.alternativeTestMOC];
    }
    if (self.searchMOC != nil) {
        [result addObject:self.searchMOC];
    }
    if (self.mockTransportSession.managedObjectContext != nil) {
        [result addObject:self.mockTransportSession.managedObjectContext];
    }

    return result;
}

- (NSArray *)allDispatchGroups;
{
    NSMutableArray *groups = [NSMutableArray array];
    [groups addObject:self.dispatchGroup];
    for (NSManagedObjectContext *moc in self.allManagedObjectContexts) {
        [groups addObject:moc.dispatchGroup];
    }
    return groups;
}


- (XCTestExpectation *)expectationForSaveOnContext:(NSManagedObjectContext *)moc withUpdateOfClass:(Class)aClass handler:(SaveExpectationHandler)handler;
{
    return [self expectationForNotification:NSManagedObjectContextDidSaveNotification object:moc handler:^BOOL(NSNotification *notification) {
        NSSet *updated = notification.userInfo[NSUpdatedObjectsKey];
        for (ZMManagedObject *mo in updated) {
            if ([mo isKindOfClass:aClass] &&
                handler(mo))
            {
                return YES;
            }
        }
        return NO;
    }];
}

@end



@implementation MessagingTest (UserTesting)

- (void)setEmailAddress:(NSString *)emailAddress onUser:(ZMUser *)user;
{
    user.emailAddress = emailAddress;
}

- (void)setPhoneNumber:(NSString *)phoneNumber onUser:(ZMUser *)user;
{
    user.phoneNumber = phoneNumber;
}

@end



@implementation MessagingTest (FilesInCache)

+ (NSURL *)cacheFolder {
    return (NSURL *)[[NSFileManager defaultManager] URLsForDirectory:NSCachesDirectory inDomains:NSUserDomainMask].firstObject;
}

+ (void)deleteAllFilesInCache {
    NSFileManager *fm = [NSFileManager defaultManager];
    for(NSURL *url in [self filesInCache]) {
        [fm removeItemAtURL:url error:nil];
    }
}

+ (NSSet *)filesInCache {
    return [NSSet setWithArray:[[NSFileManager defaultManager] contentsOfDirectoryAtURL:[self cacheFolder] includingPropertiesForKeys:@[NSURLNameKey] options:0 error:nil]];
}

@end


@implementation MessagingTest (OTR)

- (UserClient *)setupSelfClientInMoc:(NSManagedObjectContext *)moc;
{
    ZMUser *selfUser = [ZMUser selfUserInContext:moc];
    if (selfUser.remoteIdentifier == nil) {
        selfUser.remoteIdentifier = [NSUUID createUUID];
    }
    
    UserClient *client = [UserClient insertNewObjectInManagedObjectContext:moc];
    client.remoteIdentifier = [NSString createAlphanumericalString];
    client.user = selfUser;
    
    [moc setPersistentStoreMetadata:client.remoteIdentifier forKey:ZMPersistedClientIdKey];
    [moc saveOrRollback];
    
    return client;
}

- (UserClient *)createSelfClient
{
    UserClient *selfClient = [self setupSelfClientInMoc:self.syncMOC];
    NSDictionary *payload = @{@"id": selfClient.remoteIdentifier, @"type": @"permanent", @"time": [[NSDate date] transportString]};
    NOT_USED([UserClient createOrUpdateSelfUserClient:payload context:self.syncMOC]);
    [self.syncMOC saveOrRollback];
    
    return selfClient;
}

- (ZMClientMessage *)createClientTextMessage:(BOOL)encrypted
{
    return [self createClientTextMessage:self.name encrypted:encrypted];
}

- (ZMClientMessage *)createClientTextMessage:(NSString *)text encrypted:(BOOL)encrypted
{
    ZMClientMessage *message = [ZMClientMessage insertNewObjectInManagedObjectContext:self.syncMOC];
    NSUUID *messageNonce = [NSUUID createUUID];
    ZMGenericMessage *textMessage = [ZMGenericMessage messageWithText:text nonce:messageNonce.transportString expiresAfter:nil];
    [message addData:textMessage.data];
    message.isEncrypted = encrypted;
    return message;
}

- (ZMAssetClientMessage *)createImageMessageWithImageData:(NSData *)imageData format:(ZMImageFormat)format processed:(BOOL)processed stored:(BOOL)stored encrypted:(BOOL)encrypted moc:(NSManagedObjectContext *)moc
{
    NSUUID *nonce = [NSUUID createUUID];
    ZMAssetClientMessage *imageMessage = [ZMAssetClientMessage assetClientMessageWithOriginalImage:imageData nonce:nonce managedObjectContext:moc expiresAfter:0];
    imageMessage.isEncrypted = encrypted;
    
    if(processed) {
        
        CGSize imageSize = [ZMImagePreprocessor sizeOfPrerotatedImageWithData:imageData];
        ZMIImageProperties *properties = [ZMIImageProperties imagePropertiesWithSize:imageSize
                                                                              length:imageData.length
                                                                            mimeType:@"image/jpeg"];
        ZMImageAssetEncryptionKeys *keys = nil;
        if (encrypted) {
            keys = [[ZMImageAssetEncryptionKeys alloc] initWithOtrKey:[NSData zmRandomSHA256Key]
                                                               macKey:[NSData zmRandomSHA256Key]
                                                                  mac:[NSData zmRandomSHA256Key]];
        }
        
        ZMGenericMessage *message = [ZMGenericMessage genericMessageWithMediumImageProperties:properties processedImageProperties:properties encryptionKeys:keys nonce:nonce.transportString format:format expiresAfter:nil];
        [imageMessage add:message];
        
        ImageAssetCache *directory = self.uiMOC.zm_imageAssetCache;
        if (stored) {
            [directory storeAssetData:nonce format:ZMImageFormatOriginal encrypted:NO data:imageData];
        }
        if (processed) {
            [directory storeAssetData:nonce format:format encrypted:NO data:imageData];
        }
        if (encrypted) {
            [directory storeAssetData:nonce format:format encrypted:YES data:imageData];
        }
    }
    return imageMessage;
}

@end


@implementation  MessagingTest (SwiftBridgeConversation)

- (void)simulateUnreadCount:(NSUInteger)unreadCount forConversation:(ZMConversation *)conversation;
{
    BOOL isSyncContext = conversation.managedObjectContext.zm_isSyncContext;
    [self.syncMOC performGroupedBlockAndWait:^{
        ZMConversation *syncConv = conversation;
        if (!isSyncContext) {
            NSManagedObjectID *objectID = conversation.objectID;
            syncConv = (id)[self.syncMOC objectWithID:objectID];
        }
        syncConv.internalEstimatedUnreadCount = [@(unreadCount) intValue];
        [self.syncMOC saveOrRollback];
    }];
    if (!isSyncContext) {
        [self.uiMOC refreshObject:conversation mergeChanges:YES];
    }
}

- (void)simulateUnreadMissedCallInConversation:(ZMConversation *)conversation;
{
    BOOL isSyncContext = conversation.managedObjectContext.zm_isSyncContext;
    [self.syncMOC performGroupedBlockAndWait:^{
        ZMConversation *syncConv = conversation;
        if (!isSyncContext) {
            NSManagedObjectID *objectID = conversation.objectID;
            syncConv = (id)[self.syncMOC objectWithID:objectID];
        }
        syncConv.lastUnreadMissedCallDate = [NSDate date];
        [self.syncMOC saveOrRollback];
    }];
    if (!isSyncContext) {
        [self.uiMOC refreshObject:conversation mergeChanges:YES];
    }
}


- (void)simulateUnreadMissedKnockInConversation:(ZMConversation *)conversation;
{
    BOOL isSyncContext = conversation.managedObjectContext.zm_isSyncContext;
    [self.syncMOC performGroupedBlockAndWait:^{
        ZMConversation *syncConv = conversation;
        if (!isSyncContext) {
            NSManagedObjectID *objectID = conversation.objectID;
            syncConv = (id)[self.syncMOC objectWithID:objectID];
        }
        syncConv.lastUnreadKnockDate = [NSDate date];
        [self.syncMOC saveOrRollback];
    }];
    if (!isSyncContext) {
        [self.uiMOC refreshObject:conversation mergeChanges:YES];
    }
}

@end
