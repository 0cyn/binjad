#import <Cocoa/Cocoa.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>

namespace {
	NSString* const kGitHubUrl = @"https://github.com/0cyn/binjad";
	constexpr CGFloat kStatusWidgetWidth = 300.0;
	constexpr CGFloat kStatusWidgetHeight = 108.0;
	constexpr CGFloat kStatusPanelInset = 16.0;
	constexpr CGFloat kStatusColumnWidth = (kStatusWidgetWidth - (2.0 * kStatusPanelInset)) / 3.0;

	NSString* ArgumentValue(NSArray<NSString*>* arguments, NSString* name)
	{
		const NSUInteger index = [arguments indexOfObject:name];
		if (index == NSNotFound || index + 1 >= arguments.count)
			return nil;
		return arguments[index + 1];
	}

	NSArray<NSArray<NSString*>*>* ToolkitDefinitions()
	{
		static NSArray<NSArray<NSString*>*>* definitions = @[
			@[@"project_management", @"Project Management & Documents"],
			@[@"function_analysis", @"Function Analysis"],
			@[@"binary_data", @"Binary Data"],
			@[@"search", @"Search"],
			@[@"types", @"Types & Signatures"],
			@[@"annotations", @"Annotations & Symbols"],
			@[@"binary_editing", @"Binary Editing"],
			@[@"history", @"Transactions & History"],
			@[@"header_parsing", @"Header Parsing"],
			@[@"url_generation", @"URL Generation"],
			@[@"diffing", @"Diffing"],
			@[@"kernel_cache", @"KernelCache"],
			@[@"shared_cache", @"SharedCache"],
			@[@"debugger", @"Debugger"],
		];
		return definitions;
	}

	NSDictionary* ToolControlRequest(NSString* socketPath, NSDictionary* request)
	{
		NSData* encoded = [NSJSONSerialization dataWithJSONObject:request options:0 error:nil];
		if (!encoded)
			return nil;
		NSMutableData* line = [encoded mutableCopy];
		const char newline = '\n';
		[line appendBytes:&newline length:1];

		const char* path = socketPath.fileSystemRepresentation;
		if (!path || std::strlen(path) >= sizeof(sockaddr_un::sun_path))
			return nil;
		const int socket = ::socket(AF_UNIX, SOCK_STREAM, 0);
		if (socket < 0)
			return nil;
		if (::fcntl(socket, F_SETFD, FD_CLOEXEC) != 0)
		{
			::close(socket);
			return nil;
		}
		const timeval timeout {2, 0};
		::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
		sockaddr_un address {};
		address.sun_family = AF_UNIX;
		std::memcpy(address.sun_path, path, std::strlen(path) + 1);
		if (::connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
		{
			::close(socket);
			return nil;
		}

		const auto* bytes = static_cast<const std::uint8_t*>(line.bytes);
		std::size_t remaining = line.length;
		while (remaining != 0)
		{
			const auto count = ::send(socket, bytes, remaining, MSG_NOSIGNAL);
			if (count < 0)
			{
				if (errno == EINTR)
					continue;
				::close(socket);
				return nil;
			}
			if (count == 0)
			{
				::close(socket);
				return nil;
			}
			bytes += count;
			remaining -= static_cast<std::size_t>(count);
		}
		::shutdown(socket, SHUT_WR);

		NSMutableData* response = [NSMutableData data];
		std::array<char, 1024> buffer {};
		while (response.length <= 65536)
		{
			const auto count = ::recv(socket, buffer.data(), buffer.size(), 0);
			if (count > 0)
			{
				[response appendBytes:buffer.data() length:static_cast<NSUInteger>(count)];
				if (std::memchr(buffer.data(), '\n', static_cast<std::size_t>(count)))
					break;
				continue;
			}
			if (count < 0 && errno == EINTR)
				continue;
			break;
		}
		::close(socket);
		if (!response.length || response.length > 65536)
			return nil;
		id decoded = [NSJSONSerialization JSONObjectWithData:response options:0 error:nil];
		return [decoded isKindOfClass:[NSDictionary class]] ? decoded : nil;
	}
}

@interface BinjadStatusCardBackground : NSView
@end

@implementation BinjadStatusCardBackground

- (BOOL)isOpaque
{
	return NO;
}

- (void)viewDidChangeEffectiveAppearance
{
	[super viewDidChangeEffectiveAppearance];
	self.needsDisplay = YES;
}

- (void)drawRect:(NSRect)dirtyRect
{
	(void)dirtyRect;
	NSString* match = [self.effectiveAppearance bestMatchFromAppearancesWithNames:
		@[NSAppearanceNameAqua, NSAppearanceNameDarkAqua]];
	const BOOL dark = [match isEqualToString:NSAppearanceNameDarkAqua];
	NSBezierPath* card = [NSBezierPath bezierPathWithRoundedRect:NSInsetRect(self.bounds, 8.0, 8.0)
		xRadius:8.0
		yRadius:8.0];

	[NSGraphicsContext saveGraphicsState];
	NSShadow* shadow = [[NSShadow alloc] init];
	shadow.shadowColor = [NSColor colorWithWhite:0.0 alpha:dark ? 0.82 : 0.42];
	shadow.shadowBlurRadius = 7.0;
	shadow.shadowOffset = NSMakeSize(0.0, -2.0);
	[shadow set];
	[[NSColor colorWithWhite:1.0 alpha:dark ? 0.10 : 0.72] setFill];
	[card fill];
	[NSGraphicsContext restoreGraphicsState];

	[[NSColor colorWithWhite:dark ? 1.0 : 0.0 alpha:dark ? 0.13 : 0.09] setStroke];
	card.lineWidth = 0.5;
	[card stroke];
}

@end

@interface BinjadMenuBarDelegate : NSObject <NSApplicationDelegate, NSMenuDelegate>
@property(nonatomic, strong) NSStatusItem* statusItem;
@property(nonatomic, strong) NSMenuItem* startItem;
@property(nonatomic, strong) NSMenuItem* stopItem;
@property(nonatomic, strong) NSMenuItem* restartItem;
@property(nonatomic, strong) NSMenuItem* toolkitStatusItem;
@property(nonatomic, strong) NSMenuItem* toolkitStatusSeparator;
@property(nonatomic, copy) NSDictionary<NSString*, NSMenuItem*>* toolkitItems;
@property(nonatomic, copy) NSArray<NSTextField*>* metricValues;
@property(nonatomic, copy) NSString* brewPath;
@property(nonatomic, copy) NSString* formula;
@property(nonatomic, copy) NSString* serviceTarget;
@property(nonatomic, copy) NSString* configPath;
@property(nonatomic, copy) NSString* controlSocketPath;
@property(nonatomic, copy) NSString* portalUrl;
@property(nonatomic, strong) NSTimer* statusTimer;
@property(nonatomic, strong) NSURLSession* statusSession;
@property(nonatomic) BOOL serviceLoaded;
@property(nonatomic) BOOL operationInFlight;
@property(nonatomic) BOOL statusCheckInFlight;
@property(nonatomic) BOOL runtimeStatusInFlight;
@property(nonatomic) BOOL toolControlInFlight;
@end

@implementation BinjadMenuBarDelegate

- (instancetype)initWithArguments:(NSArray<NSString*>*)arguments
{
	self = [super init];
	if (!self)
		return nil;

	_brewPath = [ArgumentValue(arguments, @"--brew-path") copy];
	_formula = [ArgumentValue(arguments, @"--formula") copy];
	_configPath = [ArgumentValue(arguments, @"--config-path") copy];
	_controlSocketPath = [ArgumentValue(arguments, @"--control-socket") copy];
	_portalUrl = [ArgumentValue(arguments, @"--portal-url") copy];
	NSString* label = ArgumentValue(arguments, @"--service-label");
	if (!_brewPath.length || !_formula.length || !_configPath.length || !_controlSocketPath.length
		|| !_portalUrl.length || !label.length)
		return nil;
	_serviceTarget = [[NSString stringWithFormat:@"gui/%u/%@", getuid(), label] copy];
	_serviceLoaded = YES;
	return self;
}

- (NSTextField*)labelWithText:(NSString*)text frame:(NSRect)frame font:(NSFont*)font color:(NSColor*)color
{
	NSTextField* label = [NSTextField labelWithString:text];
	label.frame = frame;
	label.font = font;
	label.textColor = color;
	label.alignment = NSTextAlignmentCenter;
	label.lineBreakMode = NSLineBreakByTruncatingTail;
	return label;
}

- (NSView*)statusWidgetView
{
	NSView* widget = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, kStatusWidgetWidth, kStatusWidgetHeight)];
	BinjadStatusCardBackground* background = [[BinjadStatusCardBackground alloc]
		initWithFrame:NSMakeRect(8.0, 2.0, kStatusWidgetWidth - 16.0, kStatusWidgetHeight - 4.0)];
	[widget addSubview:background];

	NSArray<NSString*>* captions = @[@"Sessions", @"Open Items", @"Memory", @"Active", @"Queued"];
	NSMutableArray<NSTextField*>* values = [NSMutableArray arrayWithCapacity:captions.count];
	for (NSUInteger index = 0; index < captions.count; ++index)
	{
		const CGFloat x = kStatusPanelInset + static_cast<CGFloat>(index % 3) * kStatusColumnWidth;
		const CGFloat bottom = index < 3 ? 54.0 : 20.0;
		NSTextField* value = [self labelWithText:@"-"
			frame:NSMakeRect(x + 2.0, bottom + 12.0, kStatusColumnWidth - 4.0, 20.0)
			font:[NSFont monospacedDigitSystemFontOfSize:15.0 weight:NSFontWeightSemibold]
			color:NSColor.labelColor];
		NSTextField* caption = [self labelWithText:captions[index]
			frame:NSMakeRect(x + 2.0, bottom, kStatusColumnWidth - 4.0, 12.0)
			font:[NSFont systemFontOfSize:8.5 weight:NSFontWeightRegular]
			color:NSColor.secondaryLabelColor];
		[widget addSubview:value];
		[widget addSubview:caption];
		[values addObject:value];
	}
	self.metricValues = values;
	return widget;
}

- (void)applicationDidFinishLaunching:(NSNotification*)notification
{
	(void)notification;
	self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
	NSString* imagePath = [[NSBundle mainBundle] pathForResource:@"menubar" ofType:@"png"];
	NSImage* image = [[NSImage alloc] initWithContentsOfFile:imagePath];
	[image setTemplate:YES];
	image.size = NSMakeSize(18.0, 18.0);
	self.statusItem.button.image = image;
	self.statusItem.button.imagePosition = NSImageOnly;
	self.statusItem.button.toolTip = @"binjad";

	NSMenu* menu = [[NSMenu alloc] initWithTitle:@"binjad"];
	menu.delegate = self;
	NSMenuItem* statusWidget = [[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""];
	statusWidget.view = [self statusWidgetView];
	[menu addItem:statusWidget];
	[menu addItem:[NSMenuItem separatorItem]];

	NSMenuItem* toolkits = [menu addItemWithTitle:@"Toolkits" action:nil keyEquivalent:@""];
	NSMenu* toolkitsMenu = [[NSMenu alloc] initWithTitle:@"Toolkits"];
	toolkitsMenu.delegate = self;
	NSMenuItem* core = [toolkitsMenu addItemWithTitle:@"Core Workflow" action:nil keyEquivalent:@""];
	core.state = NSControlStateValueOn;
	core.enabled = NO;
	[toolkitsMenu addItem:[NSMenuItem separatorItem]];
	NSMutableDictionary<NSString*, NSMenuItem*>* toolkitItems = [NSMutableDictionary dictionary];
	for (NSArray<NSString*>* definition in ToolkitDefinitions())
	{
		NSMenuItem* item =
			[toolkitsMenu addItemWithTitle:definition[1] action:@selector(toggleToolkit:) keyEquivalent:@""];
		item.target = self;
		item.representedObject = definition[0];
		item.enabled = NO;
		toolkitItems[definition[0]] = item;
	}
	self.toolkitStatusSeparator = [NSMenuItem separatorItem];
	[toolkitsMenu addItem:self.toolkitStatusSeparator];
	self.toolkitStatusItem = [toolkitsMenu addItemWithTitle:@"Toolkits unavailable" action:nil keyEquivalent:@""];
	self.toolkitStatusItem.enabled = NO;
	self.toolkitItems = toolkitItems;
	toolkits.submenu = toolkitsMenu;
	[menu addItem:[NSMenuItem separatorItem]];

	self.startItem = [menu addItemWithTitle:@"Start Daemon" action:@selector(startDaemon:) keyEquivalent:@""];
	self.stopItem = [menu addItemWithTitle:@"Stop Daemon" action:@selector(stopDaemon:) keyEquivalent:@""];
	self.restartItem =
		[menu addItemWithTitle:@"Restart Daemon" action:@selector(restartDaemon:) keyEquivalent:@""];
	self.startItem.target = self;
	self.stopItem.target = self;
	self.restartItem.target = self;
	[menu addItem:[NSMenuItem separatorItem]];

	NSMenuItem* github = [menu addItemWithTitle:@"GitHub" action:@selector(openGitHub:) keyEquivalent:@""];
	github.target = self;
	NSMenuItem* credit = [menu addItemWithTitle:@"by 0cyn, with love" action:nil keyEquivalent:@""];
	credit.enabled = NO;
	[menu addItem:[NSMenuItem separatorItem]];
	NSMenuItem* portal =
		[menu addItemWithTitle:@"Open Web Portal" action:@selector(openPortal:) keyEquivalent:@""];
	portal.target = self;

	self.statusItem.menu = menu;
	NSURLSessionConfiguration* sessionConfiguration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
	sessionConfiguration.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
	sessionConfiguration.timeoutIntervalForRequest = 2.0;
	self.statusSession = [NSURLSession sessionWithConfiguration:sessionConfiguration];
	[self updateControlState];
	[self refreshServiceState];
	[self refreshRuntimeStatus];
	[self refreshToolkits];
	__weak BinjadMenuBarDelegate* weakSelf = self;
	self.statusTimer = [NSTimer scheduledTimerWithTimeInterval:3.0
		repeats:YES
		block:^(NSTimer* timer) {
			(void)timer;
			[weakSelf refreshServiceState];
			[weakSelf refreshRuntimeStatus];
		}];
}

- (void)menuWillOpen:(NSMenu*)menu
{
	(void)menu;
	[self refreshServiceState];
	[self refreshRuntimeStatus];
	[self refreshToolkits];
}

- (void)updateControlState
{
	self.startItem.enabled = !self.operationInFlight && !self.serviceLoaded;
	self.stopItem.enabled = !self.operationInFlight && self.serviceLoaded;
	self.restartItem.enabled = !self.operationInFlight && self.serviceLoaded;
}

- (void)setToolkitControlsAvailable:(BOOL)available
{
	for (NSMenuItem* item in self.toolkitItems.allValues)
		item.enabled = available && !self.toolControlInFlight;
	if (!available)
	{
		if (self.toolkitStatusItem.hidden)
			self.toolkitStatusItem.title = @"Toolkits unavailable";
		self.toolkitStatusSeparator.hidden = NO;
		self.toolkitStatusItem.hidden = NO;
	}
}

- (void)performToolControlRequest:(NSDictionary*)request
{
	if (self.toolControlInFlight)
		return;
	self.toolControlInFlight = YES;
	self.toolkitStatusItem.title = @"Updating toolkits...";
	self.toolkitStatusItem.hidden = NO;
	self.toolkitStatusSeparator.hidden = NO;
	[self setToolkitControlsAvailable:NO];
	NSString* socketPath = self.controlSocketPath;
	__weak BinjadMenuBarDelegate* weakSelf = self;
	dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
		NSDictionary* response = ToolControlRequest(socketPath, request);
		dispatch_async(dispatch_get_main_queue(), ^{
			BinjadMenuBarDelegate* strongSelf = weakSelf;
			if (!strongSelf)
				return;
			strongSelf.toolControlInFlight = NO;
			NSDictionary* packs = [response[@"packs"] isKindOfClass:[NSDictionary class]] ? response[@"packs"] : nil;
			if (![response[@"ok"] boolValue] || !packs)
			{
				strongSelf.toolkitStatusItem.title = @"Toolkit update failed";
				strongSelf.toolkitStatusItem.hidden = NO;
				strongSelf.toolkitStatusSeparator.hidden = NO;
				[strongSelf setToolkitControlsAvailable:NO];
				return;
			}
			for (NSString* key in strongSelf.toolkitItems)
			{
				NSNumber* enabled = [packs[key] isKindOfClass:[NSNumber class]] ? packs[key] : nil;
				strongSelf.toolkitItems[key].state = enabled.boolValue ? NSControlStateValueOn : NSControlStateValueOff;
			}
			strongSelf.toolkitStatusItem.hidden = YES;
			strongSelf.toolkitStatusSeparator.hidden = YES;
			[strongSelf setToolkitControlsAvailable:strongSelf.serviceLoaded];
		});
	});
}

- (void)refreshToolkits
{
	if (!self.serviceLoaded)
	{
		self.toolkitStatusItem.title = @"Toolkits unavailable";
		self.toolkitStatusItem.hidden = NO;
		self.toolkitStatusSeparator.hidden = NO;
		[self setToolkitControlsAvailable:NO];
		return;
	}
	[self performToolControlRequest:@{@"operation": @"list"}];
}

- (void)toggleToolkit:(NSMenuItem*)item
{
	NSString* key = [item.representedObject isKindOfClass:[NSString class]] ? item.representedObject : nil;
	if (!key.length)
		return;
	const BOOL enabled = item.state != NSControlStateValueOn;
	[self performToolControlRequest:@{@"operation": @"set", @"pack": key, @"enabled": @(enabled)}];
}

- (NSDictionary*)loadedConfiguration
{
	NSData* data = [NSData dataWithContentsOfFile:self.configPath];
	id root = data ? [NSJSONSerialization JSONObjectWithData:data options:0 error:nil] : nil;
	return [root isKindOfClass:[NSDictionary class]] ? root : nil;
}

- (NSURL*)runtimeStatusUrl
{
	NSDictionary* root = [self loadedConfiguration];
	NSDictionary* listener = [root[@"listener"] isKindOfClass:[NSDictionary class]] ? root[@"listener"] : @{};
	NSArray* addresses = [listener[@"addresses"] isKindOfClass:[NSArray class]] ? listener[@"addresses"] : @[];
	NSString* address = addresses.count && [addresses[0] isKindOfClass:[NSString class]] ?
		addresses[0] : @"127.0.0.1";
	if ([address containsString:@":"] && ![address hasPrefix:@"["])
		address = [NSString stringWithFormat:@"[%@]", address];
	NSNumber* port = [listener[@"port"] isKindOfClass:[NSNumber class]] ? listener[@"port"] : @8712;
	NSDictionary* http = [root[@"http"] isKindOfClass:[NSDictionary class]] ? root[@"http"] : @{};
	NSString* healthPath = [http[@"health_path"] isKindOfClass:[NSString class]] ? http[@"health_path"] : @"/healthz";
	NSString* value = [NSString stringWithFormat:@"http://%@:%llu%@/status", address,
		port.unsignedLongLongValue, healthPath];
	return [NSURL URLWithString:value];
}

- (void)clearRuntimeStatus
{
	for (NSTextField* value in self.metricValues)
		value.stringValue = @"-";
}

- (void)refreshRuntimeStatus
{
	if (self.runtimeStatusInFlight)
		return;
	if (!self.serviceLoaded)
	{
		[self clearRuntimeStatus];
		return;
	}
	NSURL* url = [self runtimeStatusUrl];
	if (!url)
	{
		[self clearRuntimeStatus];
		return;
	}

	self.runtimeStatusInFlight = YES;
	__weak BinjadMenuBarDelegate* weakSelf = self;
	NSURLSessionDataTask* task = [self.statusSession dataTaskWithURL:url
		completionHandler:^(NSData* data, NSURLResponse* response, NSError* error) {
			NSDictionary* status = nil;
			if (!error && [response isKindOfClass:[NSHTTPURLResponse class]]
				&& static_cast<NSHTTPURLResponse*>(response).statusCode == 200 && data)
			{
				id decoded = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
				if ([decoded isKindOfClass:[NSDictionary class]])
					status = decoded;
			}
			NSArray<NSString*>* keys = @[
				@"analysis_sessions", @"open_items", @"memory_bytes", @"active_analyses", @"queued_analyses"];
			dispatch_async(dispatch_get_main_queue(), ^{
				BinjadMenuBarDelegate* strongSelf = weakSelf;
				if (!strongSelf)
					return;
				strongSelf.runtimeStatusInFlight = NO;
				for (NSUInteger index = 0; index < keys.count; ++index)
				{
					NSNumber* number = [status[keys[index]] isKindOfClass:[NSNumber class]] ? status[keys[index]] : nil;
					strongSelf.metricValues[index].stringValue = index == 2 && number ?
						[NSByteCountFormatter stringFromByteCount:number.longLongValue
							countStyle:NSByteCountFormatterCountStyleMemory] :
						(number ? number.stringValue : @"-");
				}
			});
		}];
	[task resume];
}

- (NSTask*)taskWithExecutable:(NSString*)executable arguments:(NSArray<NSString*>*)arguments
{
	NSTask* task = [[NSTask alloc] init];
	task.executableURL = [NSURL fileURLWithPath:executable];
	task.arguments = arguments;
	task.standardInput = [NSFileHandle fileHandleWithNullDevice];
	task.standardOutput = [NSFileHandle fileHandleWithNullDevice];
	task.standardError = [NSFileHandle fileHandleWithNullDevice];
	return task;
}

- (void)refreshServiceState
{
	if (self.statusCheckInFlight || self.operationInFlight)
		return;
	self.statusCheckInFlight = YES;
	NSTask* task = [self taskWithExecutable:@"/bin/launchctl" arguments:@[@"print", self.serviceTarget]];
	__weak BinjadMenuBarDelegate* weakSelf = self;
	task.terminationHandler = ^(NSTask* completedTask) {
		dispatch_async(dispatch_get_main_queue(), ^{
			BinjadMenuBarDelegate* strongSelf = weakSelf;
			if (!strongSelf)
				return;
			strongSelf.statusCheckInFlight = NO;
			strongSelf.serviceLoaded = completedTask.terminationStatus == 0;
			if (!strongSelf.serviceLoaded)
			{
				[strongSelf clearRuntimeStatus];
				strongSelf.toolkitStatusItem.title = @"Toolkits unavailable";
				strongSelf.toolkitStatusItem.hidden = NO;
				strongSelf.toolkitStatusSeparator.hidden = NO;
				[strongSelf setToolkitControlsAvailable:NO];
			}
			else
				[strongSelf refreshRuntimeStatus];
			[strongSelf updateControlState];
		});
	};
	NSError* error = nil;
	if (![task launchAndReturnError:&error])
	{
		self.statusCheckInFlight = NO;
		NSLog(@"binjad menu bar could not inspect the service: %@", error.localizedDescription);
		[self updateControlState];
	}
}

- (void)runBrewServiceAction:(NSString*)action
{
	if (self.operationInFlight)
		return;
	self.operationInFlight = YES;
	[self updateControlState];

	NSTask* task = [self taskWithExecutable:self.brewPath arguments:@[@"services", action, self.formula]];
	__weak BinjadMenuBarDelegate* weakSelf = self;
	task.terminationHandler = ^(NSTask* completedTask) {
		dispatch_async(dispatch_get_main_queue(), ^{
			BinjadMenuBarDelegate* strongSelf = weakSelf;
			if (!strongSelf)
				return;
			strongSelf.operationInFlight = NO;
			if (completedTask.terminationStatus != 0)
				NSLog(@"binjad menu bar: brew services %@ failed with status %d", action,
					completedTask.terminationStatus);
			[strongSelf refreshServiceState];
			[strongSelf updateControlState];
		});
	};
	NSError* error = nil;
	if (![task launchAndReturnError:&error])
	{
		self.operationInFlight = NO;
		NSLog(@"binjad menu bar could not run brew services: %@", error.localizedDescription);
		[self refreshServiceState];
		[self updateControlState];
	}
}

- (void)startDaemon:(id)sender
{
	(void)sender;
	[self runBrewServiceAction:@"start"];
}

- (void)stopDaemon:(id)sender
{
	(void)sender;
	[self runBrewServiceAction:@"stop"];
}

- (void)restartDaemon:(id)sender
{
	(void)sender;
	[self runBrewServiceAction:@"restart"];
}

- (void)openGitHub:(id)sender
{
	(void)sender;
	[[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:kGitHubUrl]];
}

- (void)openPortal:(id)sender
{
	(void)sender;
	NSString* portalUrl = self.portalUrl;
	NSDictionary* root = [self loadedConfiguration];
	if ([root isKindOfClass:[NSDictionary class]])
	{
		NSDictionary* http = [root[@"http"] isKindOfClass:[NSDictionary class]] ? root[@"http"] : @{};
		NSString* base = [http[@"public_base_url"] isKindOfClass:[NSString class]] ? http[@"public_base_url"] : @"";
		if (!base.length)
		{
			NSDictionary* listener =
				[root[@"listener"] isKindOfClass:[NSDictionary class]] ? root[@"listener"] : @{};
			NSArray* addresses =
				[listener[@"addresses"] isKindOfClass:[NSArray class]] ? listener[@"addresses"] : @[];
			NSString* address = addresses.count && [addresses[0] isKindOfClass:[NSString class]] ?
				addresses[0] : @"127.0.0.1";
			NSNumber* port = [listener[@"port"] isKindOfClass:[NSNumber class]] ? listener[@"port"] : @8712;
			if ([address containsString:@":"] && ![address hasPrefix:@"["])
				address = [NSString stringWithFormat:@"[%@]", address];
			base = [NSString stringWithFormat:@"http://%@:%@", address, port];
		}
		while (base.length > 1 && [base hasSuffix:@"/"])
			base = [base substringToIndex:base.length - 1];
		NSString* path = [http[@"portal_path"] isKindOfClass:[NSString class]] ? http[@"portal_path"] : @"/portal";
		portalUrl = [base stringByAppendingString:path];
	}
	[[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:portalUrl]];
}

@end

int main(int argc, const char* argv[])
{
	(void)argc;
	(void)argv;
	@autoreleasepool
	{
		NSString* bundleIdentifier = [NSBundle mainBundle].bundleIdentifier;
		for (NSRunningApplication* application in
			 [NSRunningApplication runningApplicationsWithBundleIdentifier:bundleIdentifier])
		{
			if (application.processIdentifier != NSProcessInfo.processInfo.processIdentifier
				&& !application.terminated)
				return EXIT_SUCCESS;
		}

		NSApplication* application = [NSApplication sharedApplication];
		[application setActivationPolicy:NSApplicationActivationPolicyAccessory];
		BinjadMenuBarDelegate* delegate =
			[[BinjadMenuBarDelegate alloc] initWithArguments:NSProcessInfo.processInfo.arguments];
		if (!delegate)
			return EXIT_FAILURE;
		application.delegate = delegate;
		[application run];
	}
	return EXIT_SUCCESS;
}
