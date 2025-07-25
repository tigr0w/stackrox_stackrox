import static util.Helpers.evaluateWithRetry

import com.google.protobuf.Timestamp

import io.stackrox.proto.api.v1.NetworkBaselineServiceOuterClass
import io.stackrox.proto.api.v1.NetworkBaselineServiceOuterClass.NetworkBaselineStatusPeer
import io.stackrox.proto.api.v1.NetworkBaselineServiceOuterClass.NetworkBaselinePeerStatus
import io.stackrox.proto.storage.NetworkBaselineOuterClass
import io.stackrox.proto.storage.NetworkFlowOuterClass

import common.Constants

import objects.Deployment
import services.NetworkBaselineService
import util.CollectorUtil
import util.NetworkGraphUtil
import util.Timer

import spock.lang.Tag

@Tag("PZ")
class NetworkBaselineTest extends BaseSpecification {
    private static final String SERVER_DEP_NAME = "net-bl-server"
    private static final String BASELINED_CLIENT_DEP_NAME = "net-bl-client-baselined"
    private static final String USER_DEP_NAME = "net-bl-user-server"
    private static final String BASELINED_USER_CLIENT_DEP_NAME = "net-bl-user-client-baselined"
    private static final String ANOMALOUS_CLIENT_DEP_NAME = "net-bl-client-anomalous"
    private static final String DEFERRED_BASELINED_CLIENT_DEP_NAME = "net-bl-client-deferred-baselined"
    private static final String DEFERRED_POST_LOCK_DEP_NAME = "net-bl-client-post-lock"
    static final private String MULTIPLE_EXTERNALDESTINATION = "multiple-external-destination-source"
    private static final String DATE_CMD = "date -Iseconds"

    private static final String NGINX_IMAGE = "quay.io/rhacs-eng/qa-multi-arch:nginx-1-19-alpine"
    private static final String EXTERNAL_IP1 = "8.8.8.8" // Google Public DNS
    private static final String EXTERNAL_IP2 = "1.1.1.1" // Cloudflare Public DNS
    private static final String EXTERNAL_IP3 = "142.250.72.238" // Google CDN

    // The baseline generation duration must be changed from the default for this test to succeed.
    private static final int EXPECTED_BASELINE_DURATION_SECONDS = 240

    private static final int CLOCK_SKEW_ALLOWANCE_SECONDS = 15

    private static final List<Deployment> DEPLOYMENTS = []

    private static final SERVER_DEP = createAndRegisterDeployment()
            .setName(SERVER_DEP_NAME)
            .setImage(NGINX_IMAGE)
            .addLabel("app", SERVER_DEP_NAME)
            .addPort(80)
            .setExposeAsService(true)

    private static final BASELINED_CLIENT_DEP = createAndRegisterDeployment()
            .setName(BASELINED_CLIENT_DEP_NAME)
            .setImage(NGINX_IMAGE)
            .addLabel("app", BASELINED_CLIENT_DEP_NAME)
            .setCommand(["/bin/sh", "-c",])
            .setArgs(["echo -n 'Startup time: '; ${DATE_CMD};" +
                              "for i in \$(seq 1 10); do wget --timeout=10 -S http://${SERVER_DEP_NAME};" +
                              "sleep 1; done; sleep 1000" as String])

    private static final USER_DEP = createAndRegisterDeployment()
            .setName(USER_DEP_NAME)
            .setImage(NGINX_IMAGE)
            .addLabel("app", USER_DEP_NAME)
            .addPort(80)
            .setExposeAsService(true)

    private static final BASELINED_USER_CLIENT_DEP = createAndRegisterDeployment()
            .setName(BASELINED_USER_CLIENT_DEP_NAME)
            .setImage(NGINX_IMAGE)
            .addLabel("app", BASELINED_USER_CLIENT_DEP_NAME)
            .setCommand(["/bin/sh", "-c",])
            .setArgs(["echo -n 'Startup time: '; ${DATE_CMD};" +
                              "for i in \$(seq 1 10); do wget --timeout=10 -S http://${USER_DEP_NAME};" +
                              "sleep 1; done; sleep 1000" as String])

    private static final ANOMALOUS_CLIENT_DEP = createAndRegisterDeployment()
            .setName(ANOMALOUS_CLIENT_DEP_NAME)
            .setImage(NGINX_IMAGE)
            .addLabel("app", ANOMALOUS_CLIENT_DEP_NAME)
            .setCommand(["/bin/sh", "-c",])
            .setArgs(["echo -n 'Startup time: '; ${DATE_CMD};" +
                              "echo sleeping; sleep ${EXPECTED_BASELINE_DURATION_SECONDS + 30}; echo sleep done;" +
                              "${DATE_CMD};" +
                              "for i in \$(seq 1 10); do wget --timeout=10 -S http://${SERVER_DEP_NAME}; " +
                              "sleep 1; done;" +
                              "sleep 1000" as String,])

    private static final DEFERRED_BASELINED_CLIENT_DEP = createAndRegisterDeployment()
            .setName(DEFERRED_BASELINED_CLIENT_DEP_NAME)
            .setImage(NGINX_IMAGE)
            .addLabel("app", DEFERRED_BASELINED_CLIENT_DEP_NAME)
            .setCommand(["/bin/sh", "-c",])
            .setArgs(["echo -n 'Startup time: '; ${DATE_CMD};" +
                              "while sleep 1; " +
                              "do wget --timeout=10 -S http://${SERVER_DEP_NAME}; " +
                              "done" as String,])

    private static final DEFERRED_POST_LOCK_CLIENT_DEP = createAndRegisterDeployment()
            .setName(DEFERRED_POST_LOCK_DEP_NAME)
            .setImage(NGINX_IMAGE)
            .addLabel("app", DEFERRED_POST_LOCK_DEP_NAME)
            .setCommand(["/bin/sh", "-c",])
            .setArgs(["echo -n 'Startup time: '; ${DATE_CMD};" +
                              "while sleep 1; " +
                              "do wget --timeout=10 -S http://${SERVER_DEP_NAME}; " +
                              "done" as String,])

    private static final MULTIPLE_EXTERNAL_DEP = createAndRegisterDeployment()
                    .setName(MULTIPLE_EXTERNALDESTINATION)
                    .setImage("quay.io/rhacs-eng/qa-multi-arch:nginx-1-15-4-alpine")
                    .addLabel("app", MULTIPLE_EXTERNALDESTINATION)
                    .setCommand(["/bin/sh", "-c",])
                    .setArgs(["echo -n 'Startup time: '; ${DATE_CMD};" +
                                      "while sleep ${NetworkGraphUtil.NETWORK_FLOW_UPDATE_CADENCE_IN_SECONDS}; " +
                                      "do nc -zv ${EXTERNAL_IP1} 53; nc -zv ${EXTERNAL_IP2} 53; " +
                                      "nc -zv ${EXTERNAL_IP3} 80;" +
                                      "done" as String,])

    private static createAndRegisterDeployment() {
        Deployment deployment = new Deployment()
        DEPLOYMENTS.add(deployment)
        return deployment
    }

    private batchCreate(List<Deployment> deployments) {
        orchestrator.batchCreateDeployments(deployments)
        for (Deployment deployment : deployments) {
            assert Services.waitForDeployment(deployment)
        }
    }

    // returns whether true condition was achieved
    boolean retryUntilTrue(Closure<Boolean> closure, int retries) {
        Timer timer = new Timer(retries, 10)
        while (timer.IsValid()) {
            def result = closure()
            if (result) {
                return true
            }
        }
        return false
    }

    // validateBaseline checks that `expectedPeers` are present in the baseline and `explicitMissingPeers` are not.
    // Any other peer found is going to be ignored.
    //
    // Apparently there is a TCP connection via port 9537 that gets started in OpenShift clusters against any pod with
    // exposed ports. This was causing the test to fail since the expected baseline didn't match the size of the actual.
    // Although the anomalous flow filtering was working correctly, the additional flow shown in the baseline was coming
    // from this OpenShift connection in port 9537. To fix the issue, the split between `expectedPeers` and
    // `explicitMissingPeers` was introduced.
    // Check issues ROX-11142 and PR#2459 for more information.
    def validateBaseline(NetworkBaselineOuterClass.NetworkBaseline baseline,
                         long beforeCreate,
                         long justAfterCreate,
                         List<Tuple2<String, Boolean>> mustBeInBaseline,
                         List<String> mustNotBeInBaseline) {
        assert baseline.getObservationPeriodEnd().getSeconds() > beforeCreate - CLOCK_SKEW_ALLOWANCE_SECONDS
        assert baseline.getObservationPeriodEnd().getSeconds() <
            justAfterCreate + EXPECTED_BASELINE_DURATION_SECONDS + CLOCK_SKEW_ALLOWANCE_SECONDS
        assert baseline.getForbiddenPeersCount() == 0

        for (def i = 0; i < mustBeInBaseline.size(); i++) {
            def expectedPeerID = mustBeInBaseline.get(i).getFirst()
            def expectedPeerIngress = mustBeInBaseline.get(i).getSecond()
            def actualPeer = baseline.getPeersList().find { it.getEntity().getInfo().getId() == expectedPeerID }
            assert actualPeer
            def entityInfo = actualPeer.getEntity().getInfo()
            assert entityInfo.getType() == NetworkFlowOuterClass.NetworkEntityInfo.Type.DEPLOYMENT
            assert entityInfo.getId() == expectedPeerID
            assert actualPeer.getPropertiesCount() == 1
            def properties = actualPeer.getProperties(0)
            assert properties.getIngress() == expectedPeerIngress
            assert properties.getPort() == 80
            assert properties.getProtocol() == NetworkFlowOuterClass.L4Protocol.L4_PROTOCOL_TCP
        }

        for (def checkMissingId : mustNotBeInBaseline) {
            assert !baseline.getPeersList().any { it.getEntity().getInfo().getId() == checkMissingId }
        }
        return true
    }

    def validateBaselineFull(NetworkBaselineOuterClass.NetworkBaseline baseline,
                         long beforeCreate,
                         long justAfterCreate,
                         List<NetworkBaselineStatusPeer> mustBeInBaseline,
                         List<String> mustNotBeInBaseline) {
        assert baseline.getObservationPeriodEnd().getSeconds() > beforeCreate - CLOCK_SKEW_ALLOWANCE_SECONDS
        assert baseline.getObservationPeriodEnd().getSeconds() <
            justAfterCreate + EXPECTED_BASELINE_DURATION_SECONDS + CLOCK_SKEW_ALLOWANCE_SECONDS
        assert baseline.getForbiddenPeersCount() == 0

        for (def i = 0; i < mustBeInBaseline.size(); i++) {
            def expectedPeer = mustBeInBaseline.get(i)
            def expectedPeerID = expectedPeer.getEntity().getId()
            def actualPeer = baseline.getPeersList().find { it.getEntity().getInfo().getId() == expectedPeerID }
            assert actualPeer
            def entityInfo = actualPeer.getEntity()
            assert entityInfo.getInfo().getId() == expectedPeerID
            def expectedIngress = expectedPeer.getIngress()
            def expectedPort = expectedPeer.getPort()
            def expectedProtocol = expectedPeer.getProtocol()
            def matchingProperty = actualPeer.getPropertiesList().find {
                it.getIngress() == expectedIngress &&
                it.getPort() == expectedPort &&
                it.getProtocol() == expectedProtocol
            }
            assert matchingProperty
        }

        for (def checkMissingId : mustNotBeInBaseline) {
            assert !baseline.getPeersList().any { it.getEntity().getInfo().getId() == checkMissingId }
        }
        return true
    }

    def cleanup() {
        log.info "Deleting the deployments."
        for (Deployment deployment : DEPLOYMENTS) {
            orchestrator.deleteDeployment(deployment)
        }
        CollectorUtil.deleteRuntimeConfig(orchestrator)
    }

    @Tag("NetworkBaseline")
    def "Verify network baseline functionality"() {
        when:
        "Create initial set of deployments, wait for baseline to populate"
        def beforeDeploymentCreate = System.currentTimeSeconds()
        batchCreate([SERVER_DEP, BASELINED_CLIENT_DEP])
        def justAfterDeploymentCreate = System.currentTimeSeconds()

        def serverDeploymentID = SERVER_DEP.deploymentUid
        assert serverDeploymentID != null

        def baselinedClientDeploymentID = BASELINED_CLIENT_DEP.deploymentUid
        assert baselinedClientDeploymentID != null

        Timestamp epoch = Timestamp.newBuilder().setSeconds(0).build()

        assert NetworkGraphUtil.checkForEdge(baselinedClientDeploymentID, serverDeploymentID, epoch, 180)

        // Now create the anomalous deployment
        batchCreate([ANOMALOUS_CLIENT_DEP])

        def anomalousClientDeploymentID = ANOMALOUS_CLIENT_DEP.deploymentUid
        assert anomalousClientDeploymentID != null
        log.info "Deployment IDs Server: ${serverDeploymentID}, " +
            "Baselined client: ${baselinedClientDeploymentID}, Anomalous client: ${anomalousClientDeploymentID}"

        assert NetworkGraphUtil.checkForEdge(anomalousClientDeploymentID, serverDeploymentID, epoch,
            EXPECTED_BASELINE_DURATION_SECONDS + 180, "Namespace:qa")

        def serverBaseline = evaluateWithRetry(30, 4) {
            def baseline = NetworkBaselineService.getNetworkBaseline(serverDeploymentID)
            if (baseline.getPeersCount() == 0) {
                throw new RuntimeException(
                    "No peers in baseline for deployment ${serverDeploymentID} yet. Baseline is ${baseline}"
                )
            }
            return baseline
        }
        assert serverBaseline
        def anomalousClientBaseline = NetworkBaselineService.getNetworkBaseline(anomalousClientDeploymentID)
        assert anomalousClientBaseline
        log.info "Anomalous Baseline: ${anomalousClientBaseline}"
        def baselinedClientBaseline = NetworkBaselineService.getNetworkBaseline(baselinedClientDeploymentID)
        assert baselinedClientDeploymentID

        // Deployment IDs that must be explicitly check that are missing from server baseline
        def mustNotBeInBaseline = [anomalousClientDeploymentID]

        then:
        "Validate server baseline"
        // The anomalous client->server connection should not be baselined since the anonymous client
        // sleeps for a time period longer than the observation period before connecting to the server.
        validateBaseline(serverBaseline, beforeDeploymentCreate, justAfterDeploymentCreate,
            [new Tuple2<String, Boolean>(baselinedClientDeploymentID, true)], mustNotBeInBaseline)
        validateBaseline(anomalousClientBaseline, beforeDeploymentCreate, justAfterDeploymentCreate, [], [])
        validateBaseline(baselinedClientBaseline, beforeDeploymentCreate, justAfterDeploymentCreate,
            [new Tuple2<String, Boolean>(serverDeploymentID, false)], []
        )

        when:
        "Create another deployment, ensure it gets baselined"
        def beforeDeferredCreate = System.currentTimeSeconds()
        batchCreate([DEFERRED_BASELINED_CLIENT_DEP])
        def justAfterDeferredCreate = System.currentTimeSeconds()

        def deferredBaselinedClientDeploymentID = DEFERRED_BASELINED_CLIENT_DEP.deploymentUid
        assert deferredBaselinedClientDeploymentID != null
        log.info "Deferred Baseline: ${deferredBaselinedClientDeploymentID}"

        // Waiting on it to come out of observation.
        def deferredBaselinedClientBaseline = evaluateWithRetry(30, 4) {
            def baseline = NetworkBaselineService.getNetworkBaseline(deferredBaselinedClientDeploymentID)
            def now = System.currentTimeSeconds()
            if (baseline.getObservationPeriodEnd().getSeconds() > now) {
                throw new RuntimeException(
                    "Baseline ${deferredBaselinedClientDeploymentID} is in observation. Baseline is ${baseline}"
                )
            }
            return baseline
        }
        assert deferredBaselinedClientBaseline

        assert NetworkGraphUtil.checkForEdge(deferredBaselinedClientDeploymentID, serverDeploymentID, null, 180)
        // Make sure peers have been added to the serverBaseline
        serverBaseline = evaluateWithRetry(30, 4) {
            def baseline = NetworkBaselineService.getNetworkBaseline(serverDeploymentID)
            if (baseline.getPeersCount() < 2) {
                throw new RuntimeException(
                    "Not enough peers in baseline for deployment ${serverDeploymentID} yet. Baseline is ${baseline}"
                )
            }
            return baseline
        }
        assert serverBaseline

        then:
        "Validate the updated baselines"
        validateBaseline(serverBaseline, beforeDeploymentCreate, justAfterDeploymentCreate,
            [new Tuple2<String, Boolean>(baselinedClientDeploymentID, true),
             // Currently, we add cons to the baseline if it's within the observation period
             // of _at least_ one of the deployments. Therefore, the deferred client->server connection
             // gets added since it's within the deferred client's observation period, and
             // the server's baseline is modified as well since we keep things consistent.
             new Tuple2<String, Boolean>(deferredBaselinedClientDeploymentID, true),
            ], mustNotBeInBaseline
        )
        validateBaseline(deferredBaselinedClientBaseline, beforeDeferredCreate, justAfterDeferredCreate,
            [new Tuple2<String, Boolean>(serverDeploymentID, false)], [])

        when:
        "Create another deployment, ensure it DOES NOT get added to serverDeploymentID due to user lock"
        NetworkBaselineService.lockNetworkBaseline(serverDeploymentID)

        batchCreate([DEFERRED_POST_LOCK_CLIENT_DEP])

        def postLockClientDeploymentID = DEFERRED_POST_LOCK_CLIENT_DEP.deploymentUid
        assert postLockClientDeploymentID != null
        log.info "Post Lock Deployment: ${postLockClientDeploymentID}"

        // Waiting on it to come out of observation.
        def postLockClientBaseline = evaluateWithRetry(30, 4) {
            def baseline = NetworkBaselineService.getNetworkBaseline(postLockClientDeploymentID)
            def now = System.currentTimeSeconds()
            if (baseline.getObservationPeriodEnd().getSeconds() > now) {
                throw new RuntimeException(
                    "Baseline ${postLockClientDeploymentID} is not out of observation yet. Baseline is ${baseline}"
                )
            }
            return baseline
        }
        assert postLockClientBaseline

        assert NetworkGraphUtil.checkForEdge(postLockClientDeploymentID, serverDeploymentID, null, 180)

        // Grab the latest server baseline for validation
        serverBaseline = NetworkBaselineService.getNetworkBaseline(serverDeploymentID)
        assert serverBaseline

        then:
        "Validate the locked baselines"
        // Post lock should not be added as a peer because serverBaseline is locked.
        validateBaseline(serverBaseline, beforeDeploymentCreate, justAfterDeploymentCreate,
            [new Tuple2<String, Boolean>(baselinedClientDeploymentID, true),
             new Tuple2<String, Boolean>(deferredBaselinedClientDeploymentID, true),
            ], mustNotBeInBaseline
        )
        validateBaseline(postLockClientBaseline, beforeDeferredCreate, justAfterDeferredCreate,
            [], [])

        when:
        "Verify user get for non-existent baseline"
        def beforeUserServiceDeploymentCreate = System.currentTimeSeconds()
        batchCreate([USER_DEP])
        def justAfterUserServiceDeploymentCreate = System.currentTimeSeconds()

        def userReqBaselineServerDeploymentID = USER_DEP.deploymentUid
        assert userReqBaselineServerDeploymentID != null

        log.info "Deployment IDs Server: ${userReqBaselineServerDeploymentID}"

        // Get the server baseline to simulate a user asking for a baseline prior to
        // observation ending.  This will generate a baseline at the time of request
        // instead of after observation.
        def userReqServerBaseline = NetworkBaselineService.getNetworkBaseline(userReqBaselineServerDeploymentID)
        // Ensure the baseline is STILL in the observation window
        def now = System.currentTimeSeconds()
        assert userReqServerBaseline.getObservationPeriodEnd().getSeconds() > now

        // Add a client deployment
        def beforeClientDeploymentCreate = System.currentTimeSeconds()
        batchCreate([BASELINED_USER_CLIENT_DEP])
        def justAfterClientDeploymentCreate = System.currentTimeSeconds()

        def userRequestedBaselinedClientDeploymentID = BASELINED_USER_CLIENT_DEP.deploymentUid
        assert userRequestedBaselinedClientDeploymentID != null
        log.info "Client deployment: ${userRequestedBaselinedClientDeploymentID}"

        assert retryUntilTrue({
            return NetworkGraphUtil.checkForEdge(
                userRequestedBaselinedClientDeploymentID,
                userReqBaselineServerDeploymentID)
                    .any { it.targetID == userReqBaselineServerDeploymentID }
        }, 15)

        // Grab the network baseline for the client.
        def userReqBaselinedClientBaseline =
            NetworkBaselineService.getNetworkBaseline(userRequestedBaselinedClientDeploymentID)
        assert userReqBaselinedClientBaseline

        // Grab a fresh copy of the userReqServerBaseline after the client connection has been added.
        userReqServerBaseline = NetworkBaselineService.getNetworkBaseline(userReqBaselineServerDeploymentID)

        log.info "Server Baseline: ${userReqServerBaseline}"
        log.info "Client Baseline: ${userReqBaselinedClientBaseline}"

        then:
        "Validate user requested server baseline"
        // The client->server connection should be baselined since the client as the
        // connection occurred during the observation window.
        validateBaseline(userReqServerBaseline, beforeUserServiceDeploymentCreate, justAfterUserServiceDeploymentCreate,
            [new Tuple2<String, Boolean>(userRequestedBaselinedClientDeploymentID, true)], [])
        validateBaseline(userReqBaselinedClientBaseline, beforeClientDeploymentCreate, justAfterClientDeploymentCreate,
            [new Tuple2<String, Boolean>(userReqBaselineServerDeploymentID, false)], []
        )
    }

    @Tag("NetworkBaseline")
    def "Verify network baseline functionality with multiple external entities"() {
        when:
        "External IPs is enabled and there is a deployment has multiple flows with external IPs"
        CollectorUtil.enableExternalIps(orchestrator)
        def beforeDeploymentCreate = System.currentTimeSeconds()
        batchCreate([MULTIPLE_EXTERNAL_DEP])
        def justAfterDeploymentCreate = System.currentTimeSeconds()

        def deploymentUid = MULTIPLE_EXTERNAL_DEP.deploymentUid
        assert deploymentUid != null

        Timestamp epoch = Timestamp.newBuilder().setSeconds(0).build()

        assert NetworkGraphUtil.checkForEdge(deploymentUid, Constants.INTERNET_EXTERNAL_SOURCE_ID, epoch, 180)
        def baseline = evaluateWithRetry(30, 4) {
            def baseline = NetworkBaselineService.getNetworkBaseline(deploymentUid)
            assert baseline.getPeersCount() != 0 :
                    "No peers in baseline for deployment ${deploymentUid} yet. Baseline is ${baseline}"
            return baseline
        }

        then:
        "The flows are anonymized to INTERNET when using the getNetworkBaseline endpoint"
        def mustNotBeInBaseline = []

        def expectedEntity = NetworkBaselineServiceOuterClass.NetworkBaselinePeerEntity.newBuilder()
                                .setId(Constants.INTERNET_EXTERNAL_SOURCE_ID)
                                .build()

        def expectedPeer = NetworkBaselineServiceOuterClass.NetworkBaselineStatusPeer.newBuilder()
                                                        .setEntity(expectedEntity)
                                                        .setPort(53)
                                                        .setProtocol(NetworkFlowOuterClass.L4Protocol.L4_PROTOCOL_TCP)
                                                        .setIngress(false)
                                                        .build()

        validateBaselineFull(baseline, beforeDeploymentCreate, justAfterDeploymentCreate,
            [expectedPeer], mustNotBeInBaseline)

        def externalBaseline = evaluateWithRetry(30, 4) {
            def externalBaseline = NetworkBaselineService.getNetworkBaselineForExternalFlows(deploymentUid)
            assert externalBaseline.totalAnomalous + externalBaseline.totalBaseline != 0 :
                    "No peers in baseline for deployment ${deploymentUid} yet. Baseline is ${externalBaseline}"
            return externalBaseline
        }

        then:
        "The getNetworkBaselineForExternalFlows endpoint returns all flows with external IPs"
        assert externalBaseline

        def peerStatus1 = externalBaseline.getBaselineList().find { it.getPeer().getEntity().getName() == EXTERNAL_IP1 }
        def peer1 = peerStatus1.getPeer()

        assert peer1
        def expectedEntity1 = peer1.getEntity()
        verifyAll(expectedEntity1) {
            type == NetworkFlowOuterClass.NetworkEntityInfo.Type.EXTERNAL_SOURCE
            name == EXTERNAL_IP1
            discovered == true
        }

        assert peer1.getPort() == 53
        assert peer1.getProtocol() == NetworkFlowOuterClass.L4Protocol.L4_PROTOCOL_TCP

        def peerStatus2 = externalBaseline.getBaselineList().find { it.getPeer().getEntity().getName() == EXTERNAL_IP2 }
        def peer2 = peerStatus2.getPeer()

        assert peer2
        def expectedEntity2 = peer2.getEntity()
        verifyAll(expectedEntity2) {
            type == NetworkFlowOuterClass.NetworkEntityInfo.Type.EXTERNAL_SOURCE
            name == EXTERNAL_IP2
            discovered == true
        }

        assert peer2.getPort() == 53
        assert peer2.getProtocol() == NetworkFlowOuterClass.L4Protocol.L4_PROTOCOL_TCP

        def peerStatus3 = externalBaseline.getBaselineList().find { it.getPeer().getEntity().getName() == EXTERNAL_IP3 }
        def peer3 = peerStatus3.getPeer()

        assert peer3
        def expectedEntity3 = peer3.getEntity()
        verifyAll(expectedEntity3) {
            type == NetworkFlowOuterClass.NetworkEntityInfo.Type.EXTERNAL_SOURCE
            name == EXTERNAL_IP3
            discovered == true
        }

        assert peer3.getPort() == 80
        assert peer3.getProtocol() == NetworkFlowOuterClass.L4Protocol.L4_PROTOCOL_TCP

        assert externalBaseline.getTotalBaseline() == 3
        assert externalBaseline.getTotalAnomalous() == 0

        when:
        "One of the flows is marked as anomalous"
        def status = NetworkBaselineServiceOuterClass.NetworkBaselinePeerStatus.Status.ANOMALOUS
        modifyBaseline(peer1, deploymentUid, status)

        def externalBaselineAfter = evaluateWithRetry(30, 4) {
            def externalBaselineAfter = NetworkBaselineService.getNetworkBaselineForExternalFlows(deploymentUid)
            assert externalBaselineAfter.totalAnomalous + externalBaselineAfter.totalBaseline != 0 :
                    "No peers in baseline for deployment ${deploymentUid} yet. Baseline is ${externalBaselineAfter}"
            return externalBaselineAfter
        }

        then:
        "All external flows with the same port and protocol are marked a anomalous"
        assert externalBaselineAfter.getTotalBaseline() == 1
        assert externalBaselineAfter.getTotalAnomalous() == 2

        def baselinePeerStatus = externalBaselineAfter.getBaselineList().find {
            it.getPeer().getEntity().getName() == EXTERNAL_IP3
        }
        def baselinePeer = baselinePeerStatus.getPeer()

        assert baselinePeer
        def baselineEntity = baselinePeer.getEntity()
        verifyAll(baselineEntity) {
            type == NetworkFlowOuterClass.NetworkEntityInfo.Type.EXTERNAL_SOURCE
            name == EXTERNAL_IP3
            discovered == true
        }

        assert baselinePeer.getPort() == 80
        assert baselinePeer.getProtocol() == NetworkFlowOuterClass.L4Protocol.L4_PROTOCOL_TCP

        def anomalousPeerStatus1 = externalBaselineAfter.getAnomalousList().find {
            it.getPeer().getEntity().getName() == EXTERNAL_IP1
        }
        def anomalousPeer1 = anomalousPeerStatus1.getPeer()

        assert anomalousPeer1
        def anomalousEntity1 = anomalousPeer1.getEntity()
        verifyAll(anomalousEntity1) {
            type == NetworkFlowOuterClass.NetworkEntityInfo.Type.EXTERNAL_SOURCE
            name == EXTERNAL_IP1
            discovered == true
        }

        assert anomalousPeer1.getPort() == 53
        assert anomalousPeer1.getProtocol() == NetworkFlowOuterClass.L4Protocol.L4_PROTOCOL_TCP

        def anomalousPeerStatus2 = externalBaselineAfter.getAnomalousList().find {
            it.getPeer().getEntity().getName() == EXTERNAL_IP2
        }
        def anomalousPeer2 = anomalousPeerStatus2.getPeer()

        assert anomalousPeer2
        def anomalousEntity2 = anomalousPeer2.getEntity()
        verifyAll(anomalousEntity2) {
            type == NetworkFlowOuterClass.NetworkEntityInfo.Type.EXTERNAL_SOURCE
            name == EXTERNAL_IP2
            discovered == true
        }

        assert anomalousPeer2.getPort() == 53
        assert anomalousPeer2.getProtocol() == NetworkFlowOuterClass.L4Protocol.L4_PROTOCOL_TCP
    }

    def modifyBaseline(NetworkBaselineStatusPeer peer, String deploymentUid, NetworkBaselinePeerStatus.Status status) {
        def modifiedPeer = NetworkBaselineServiceOuterClass.NetworkBaselinePeerStatus.newBuilder()
                        .setPeer(peer)
                        .setStatus(status)
                        .build()

        NetworkBaselineService.modifyBaselineStatusForPeers(deploymentUid, modifiedPeer)
    }
}
