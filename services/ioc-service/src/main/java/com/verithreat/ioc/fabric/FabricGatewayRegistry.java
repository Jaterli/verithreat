package com.verithreat.ioc.fabric;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import org.hyperledger.fabric.client.CommitException;
import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.GatewayException;
import org.hyperledger.fabric.client.Hash;
import org.hyperledger.fabric.client.identity.Identities;
import org.hyperledger.fabric.client.identity.Signers;
import org.hyperledger.fabric.client.identity.X509Identity;
import org.hyperledger.fabric.protos.gateway.ErrorDetail;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import io.grpc.Grpc;
import io.grpc.ManagedChannel;
import io.grpc.TlsChannelCredentials;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * Cliente del chaincode iocregistry con el SDK Fabric Gateway. Una conexión gRPC por organización, abierta la primera
 * vez que hace falta y reutilizada después (gRPC reconecta solo si el peer se cae y vuelve).
 */
@Component
@ConditionalOnProperty(prefix = "verithreat.fabric", name = "enabled", havingValue = "true")
public class FabricGatewayRegistry implements IocRegistry, DisposableBean {

    private static final TypeReference<List<RegistryRecord>> RECORDS = new TypeReference<>() {
    };
    /** Error del chaincode al avalar (ChaincodeException): los datos no son válidos, reintentar no sirve. */
    private static final String CHAINCODE_ERROR = "chaincode response 500";

    private record Connection(ManagedChannel channel, Gateway gateway, Contract contract) {
    }

    private final FabricProperties props;
    private final JsonMapper json;
    private final Map<String, Connection> connections = new ConcurrentHashMap<>();

    public FabricGatewayRegistry(FabricProperties props, JsonMapper json) {
        this.props = props;
        this.json = json;
    }

    @Override
    public RegistryRecord register(String organization, String type, String fingerprint, String category)
            throws RegistryException {
        Contract contract = connection(organization).contract();
        try {
            // Avala en los peers que exige la política, envía al orderer y espera a que el bloque se confirme
            byte[] result = contract.submitTransaction("RegisterIoc", type, fingerprint, category);
            return json.readValue(result, RegistryRecord.class);
        } catch (GatewayException | CommitException e) {
            throw failure("RegisterIoc", e, true);
        } catch (RuntimeException e) {
            throw new RegistryException("RegisterIoc: " + e, false, e);
        }
    }

    @Override
    public Optional<RegistryRecord> find(String organization, String type, String fingerprint)
            throws RegistryException {
        String mspId = org(organization).mspId();
        Contract contract = connection(organization).contract();
        try {
            byte[] result = contract.evaluateTransaction("GetRecordsByIndicator", fingerprint);
            return json.readValue(result, RECORDS).stream()
                    .filter(r -> mspId.equals(r.mspId()) && type.equals(r.type()))
                    .min(Comparator.comparing(RegistryRecord::registeredAt));
        } catch (GatewayException e) {
            throw failure("GetRecordsByIndicator", e, false);
        } catch (RuntimeException e) {
            throw new RegistryException("GetRecordsByIndicator: " + e, false, e);
        }
    }

    private FabricProperties.Org org(String organization) throws RegistryException {
        FabricProperties.Org org = props.organizations().get(organization);
        if (org == null) {
            throw new RegistryException("no Fabric identity configured for organization " + organization, true, null);
        }
        return org;
    }

    private Connection connection(String organization) throws RegistryException {
        Connection c = connections.get(organization);
        if (c != null) {
            return c;
        }
        FabricProperties.Org org = org(organization);
        synchronized (connections) {
            c = connections.get(organization);
            if (c == null) {
                try {
                    c = connect(org);
                } catch (IOException | GeneralSecurityException | RuntimeException e) {
                    // Ficheros de identidad ausentes (red recreada, otra ruta): se reintenta cuando se arregle
                    throw new RegistryException("cannot connect to Fabric as " + org.mspId() + ": " + e, false, e);
                }
                connections.put(organization, c);
            }
            return c;
        }
    }

    private Connection connect(FabricProperties.Org org) throws IOException, GeneralSecurityException {
        X509Certificate certificate;
        try (Reader r = Files.newBufferedReader(org.certificate())) {
            certificate = Identities.readX509Certificate(r);
        }
        PrivateKey key;
        try (Reader r = Files.newBufferedReader(keyFile(org.privateKey()))) {
            key = Identities.readPrivateKey(r);
        }
        var tls = TlsChannelCredentials.newBuilder().trustManager(org.tlsCaCertificate().toFile()).build();
        ManagedChannel channel = Grpc.newChannelBuilder(org.peerEndpoint(), tls)
                .overrideAuthority(org.peerHostOverride()).build();
        try {
            Gateway gateway = Gateway.newInstance()
                    .identity(new X509Identity(org.mspId(), certificate))
                    .signer(Signers.newPrivateKeySigner(key))
                    .hash(Hash.SHA256)
                    .connection(channel)
                    .evaluateOptions(o -> o.withDeadlineAfter(5, TimeUnit.SECONDS))
                    .endorseOptions(o -> o.withDeadlineAfter(15, TimeUnit.SECONDS))
                    .submitOptions(o -> o.withDeadlineAfter(5, TimeUnit.SECONDS))
                    .commitStatusOptions(o -> o.withDeadlineAfter(1, TimeUnit.MINUTES))
                    .connect();
            Contract contract = gateway.getNetwork(props.channel()).getContract(props.chaincode());
            return new Connection(channel, gateway, contract);
        } catch (RuntimeException e) {
            channel.shutdownNow();
            throw e;
        }
    }

    /** El keystore de las identidades de fabric-samples es un directorio con un único fichero (priv_sk). */
    private static Path keyFile(Path path) throws IOException {
        if (!Files.isDirectory(path)) {
            return path;
        }
        try (Stream<Path> files = Files.list(path)) {
            List<Path> keys = files.filter(Files::isRegularFile).toList();
            if (keys.size() != 1) {
                throw new IOException("expected exactly one key file in " + path + ", found " + keys.size());
            }
            return keys.get(0);
        }
    }

    /** {@code chaincodeErrorIsPermanent}: un rechazo del chaincode al registrar es definitivo; al consultar, no. */
    private static RegistryException failure(String action, Exception e, boolean chaincodeErrorIsPermanent) {
        StringBuilder msg = new StringBuilder(action).append(": ").append(e.getMessage());
        if (e instanceof GatewayException ge) {
            for (ErrorDetail d : ge.getDetails()) {
                msg.append("; ").append(d.getMspId()).append(' ').append(d.getAddress()).append(": ")
                        .append(d.getMessage());
            }
        }
        boolean permanent = chaincodeErrorIsPermanent && msg.indexOf(CHAINCODE_ERROR) >= 0;
        return new RegistryException(msg.toString(), permanent, e);
    }

    @Override
    public void destroy() {
        connections.values().forEach(c -> {
            c.gateway().close();
            c.channel().shutdownNow();
        });
        connections.clear();
    }
}
