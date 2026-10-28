package com.verithreat.chaincode;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import org.hyperledger.fabric.contract.ClientIdentity;
import org.hyperledger.fabric.contract.Context;
import org.hyperledger.fabric.shim.ChaincodeException;
import org.hyperledger.fabric.shim.ChaincodeStub;
import org.hyperledger.fabric.shim.ledger.CompositeKey;
import org.hyperledger.fabric.shim.ledger.KeyValue;
import org.hyperledger.fabric.shim.ledger.QueryResultsIterator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** El contrato contra un ledger simulado en memoria (un TreeMap) y una identidad de firmante simulada. */
class IocRegistryContractTest {

    private static final String FP = "a".repeat(64);
    private final IocRegistryContract contract = new IocRegistryContract();
    private final Map<String, String> ledger = new TreeMap<>();
    private Context ctx;
    private ChaincodeStub stub;
    private ClientIdentity identity;

    @BeforeEach
    void setUp() throws Exception {
        ctx = mock(Context.class);
        stub = mock(ChaincodeStub.class);
        identity = mock(ClientIdentity.class);
        when(ctx.getStub()).thenReturn(stub);
        when(ctx.getClientIdentity()).thenReturn(identity);
        when(identity.getMSPID()).thenReturn("Org1MSP");
        when(stub.getTxTimestamp()).thenReturn(Instant.parse("2026-10-27T18:00:00Z"));
        when(stub.getTxId()).thenReturn("tx-1");
        when(stub.getStringState(anyString())).thenAnswer(i -> ledger.getOrDefault(i.getArgument(0, String.class), ""));
        org.mockito.Mockito.doAnswer(i -> ledger.put(i.getArgument(0), i.getArgument(1)))
                .when(stub).putStringState(anyString(), anyString());
        // any(String[].class): cualquier número de argumentos variables (Mockito 5)
        when(stub.createCompositeKey(anyString(), org.mockito.ArgumentMatchers.any(String[].class)))
                .thenAnswer(i -> new CompositeKey((String) i.getRawArguments()[0], (String[]) i.getRawArguments()[1]));
        when(stub.splitCompositeKey(anyString())).thenAnswer(i -> CompositeKey.parseCompositeKey(i.getArgument(0)));
        when(stub.getStateByPartialCompositeKey(org.mockito.ArgumentMatchers.any(CompositeKey.class)))
                .thenAnswer(i -> iterator(i.getArgument(0, CompositeKey.class).toString()));
    }

    private QueryResultsIterator<KeyValue> iterator(String prefix) {
        List<KeyValue> rows = ledger.entrySet().stream().filter(e -> e.getKey().startsWith(prefix))
                .map(e -> kv(e.getKey(), e.getValue())).collect(Collectors.toList());
        return new QueryResultsIterator<>() {
            @Override
            public Iterator<KeyValue> iterator() {
                return rows.iterator();
            }

            @Override
            public void close() {
            }
        };
    }

    private static KeyValue kv(String k, String v) {
        return new KeyValue() {
            @Override
            public String getKey() {
                return k;
            }

            @Override
            public byte[] getValue() {
                return v.getBytes();
            }

            @Override
            public String getStringValue() {
                return v;
            }
        };
    }

    @Test
    void registersWithTheSignersOrganizationAndTheTransactionTime() {
        String json = contract.RegisterIoc(ctx, "domain", FP, "phishing");
        String expected = IocRegistryContract.sha256Hex("domain|" + FP + "|Org1MSP|2026-10-27T18:00:00Z");
        assertTrue(json.contains("\"canonicalHash\":\"" + expected + "\""), json);
        assertTrue(json.contains("\"mspId\":\"Org1MSP\""));
        assertTrue(json.contains("\"txId\":\"tx-1\""));
        assertEquals(json, ledger.get(expected));
        assertEquals(json, contract.GetRecord(ctx, expected));
    }

    @Test
    void theSameTransactionCannotRegisterTwice() {
        contract.RegisterIoc(ctx, "domain", FP, "phishing");
        ChaincodeException e = assertThrows(ChaincodeException.class,
                () -> contract.RegisterIoc(ctx, "domain", FP, "phishing"));
        assertEquals("ALREADY_REGISTERED", new String(e.getPayload()));
    }

    @Test
    void recordsByIndicatorIncludeEveryOrganization() {
        contract.RegisterIoc(ctx, "domain", FP, "phishing");
        when(identity.getMSPID()).thenReturn("Org2MSP");
        when(stub.getTxTimestamp()).thenReturn(Instant.parse("2026-10-27T18:05:00Z"));
        contract.RegisterIoc(ctx, "domain", FP, "c2");
        contract.RegisterIoc(ctx, "domain", "b".repeat(64), "c2"); // otro indicador: no debe salir
        String list = contract.GetRecordsByIndicator(ctx, FP);
        assertTrue(list.contains("Org1MSP") && list.contains("Org2MSP"), list);
        assertEquals(2, list.split("canonicalHash").length - 1, list);
    }

    @Test
    void rejectsInvalidArgumentsAndUnknownRecords() {
        assertThrows(ChaincodeException.class, () -> contract.RegisterIoc(ctx, "email", FP, "phishing"));
        assertThrows(ChaincodeException.class, () -> contract.RegisterIoc(ctx, "domain", "ABC", "phishing"));
        assertThrows(ChaincodeException.class, () -> contract.RegisterIoc(ctx, "domain", FP.toUpperCase(), "phishing"));
        assertThrows(ChaincodeException.class, () -> contract.RegisterIoc(ctx, "domain", FP, "nonsense"));
        ChaincodeException e = assertThrows(ChaincodeException.class, () -> contract.GetRecord(ctx, "f".repeat(64)));
        assertEquals("NOT_FOUND", new String(e.getPayload()));
    }
}
