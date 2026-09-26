package com.crypto.ec_calculator.service;

import com.crypto.ec_calculator.dto.ECDTOs.*;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

@Service
public class ECService {

    public ValidationResponse validateCurve(CurveParams params) {
        BigInteger a = params.a().mod(params.p());
        BigInteger b = params.b().mod(params.p());
        BigInteger p = params.p();

        // 4a^3 + 27b^2 mod p != 0
        BigInteger term1 = a.pow(3).multiply(BigInteger.valueOf(4));
        BigInteger term2 = b.pow(2).multiply(BigInteger.valueOf(27));
        BigInteger disc = term1.add(term2).mod(p);

        if (disc.equals(BigInteger.ZERO)) {
            return new ValidationResponse(false, disc, "Curva singular: 4a³ + 27b² ≡ 0 (mod p)");
        }
        return new ValidationResponse(true, disc, "Curva no singular válida.");
    }

    public List<PointDTO> getAllPoints(CurveParams params) {
        BigInteger a = params.a();
        BigInteger b = params.b();
        BigInteger p = params.p();
        List<PointDTO> points = new ArrayList<>();

        for (BigInteger x = BigInteger.ZERO; x.compareTo(p) < 0; x = x.add(BigInteger.ONE)) {
            BigInteger rhs = x.pow(3).add(a.multiply(x)).add(b).mod(p);
            for (BigInteger y = BigInteger.ZERO; y.compareTo(p) < 0; y = y.add(BigInteger.ONE)) {
                BigInteger lhs = y.modPow(BigInteger.TWO, p);
                if (lhs.equals(rhs)) {
                    points.add(new PointDTO(x, y, false));
                }
            }
        }
        return points;
    }

    public OperationResponse addPoints(CurveParams c, PointDTO p1, PointDTO p2) {
        BigInteger p = c.p();

        if (p1.isInfinity()) return new OperationResponse(p2, null, "IDENTIDAD");
        if (p2.isInfinity()) return new OperationResponse(p1, null, "IDENTIDAD");

        // P + (-P) = O
        if (p1.x().equals(p2.x()) && !p1.y().equals(p2.y())) {
            return new OperationResponse(PointDTO.infinity(), null, "INVERSO");
        }

        BigInteger m;
        String opType;

        if (p1.x().equals(p2.x()) && p1.y().equals(p2.y())) {
            if (p1.y().equals(BigInteger.ZERO)) {
                return new OperationResponse(PointDTO.infinity(), null, "TANGENTE VERTICAL");
            }
            // Doblado: m = (3*x1^2 + a) * (2*y1)^(-1) mod p
            BigInteger num = p1.x().pow(2).multiply(BigInteger.valueOf(3)).add(c.a()).mod(p);
            BigInteger den = p1.y().multiply(BigInteger.TWO).mod(p);
            m = num.multiply(den.modInverse(p)).mod(p);
            opType = "DOBLADO (2P)";
        } else {
            // Suma: m = (y2 - y1) * (x2 - x1)^(-1) mod p
            BigInteger num = p2.y().subtract(p1.y()).mod(p);
            BigInteger den = p2.x().subtract(p1.x()).mod(p);
            m = num.multiply(den.modInverse(p)).mod(p);
            opType = "SUMA (P + Q)";
        }

        BigInteger x3 = m.pow(2).subtract(p1.x()).subtract(p2.x()).mod(p);
        BigInteger y3 = m.multiply(p1.x().subtract(x3)).subtract(p1.y()).mod(p);

        return new OperationResponse(new PointDTO(x3, y3, false), m, opType);
    }

    public ScalarMultiplyResponse multiply(CurveParams c, PointDTO pt, BigInteger k) {
        if (pt.isInfinity() || k.equals(BigInteger.ZERO)) {
            return new ScalarMultiplyResponse(PointDTO.infinity(), 0, 0);
        }

        PointDTO result = PointDTO.infinity();
        PointDTO current = pt;
        int steps = 0;

        for (int i = 0; i < k.bitLength(); i++) {
            steps++;
            if (k.testBit(i)) {
                result = addPoints(c, result, current).result();
            }
            current = addPoints(c, current, current).result();
        }

        return new ScalarMultiplyResponse(result, steps, k.bitLength());
    }

    // Calcula cardinalidad, puntos y generadores
    public AnalysisResponse analyzeGroup(CurveParams params) {
        List<PointDTO> affinePoints = getAllPoints(params);
        int cardinality = affinePoints.size() + 1; // Incluye O

        List<PointDTO> allGroupPoints = new ArrayList<>();
        allGroupPoints.add(PointDTO.infinity());
        allGroupPoints.addAll(affinePoints);

        List<PointDTO> generators = new ArrayList<>();

        // Un punto G es generador si su orden ord(G) == cardinality
        for (PointDTO pt : affinePoints) {
            PointDTO acc = pt;
            int order = 1;
            while (!acc.isInfinity() && order <= cardinality) {
                acc = addPoints(params, acc, pt).result();
                order++;
            }
            if (order == cardinality) {
                generators.add(pt);
            }
        }

        return new AnalysisResponse(cardinality, affinePoints, generators);
    }

    // Matriz de suma de Cayley
    public AdditionTableResponse getAdditionTable(CurveParams params) {
        List<PointDTO> allPoints = new ArrayList<>();
        allPoints.add(PointDTO.infinity());
        allPoints.addAll(getAllPoints(params));

        List<String> headers = allPoints.stream().map(PointDTO::label).toList();
        List<List<String>> matrix = new ArrayList<>();

        for (PointDTO p1 : allPoints) {
            List<String> row = new ArrayList<>();
            for (PointDTO p2 : allPoints) {
                PointDTO res = addPoints(params, p1, p2).result();
                row.add(res.label());
            }
            matrix.add(row);
        }

        return new AdditionTableResponse(headers, matrix);
    }

    // Tabla de multiplicación escalar k * P para k = 1..cardinalidad
    public MultiplicationTableResponse getMultiplicationTable(CurveParams params) {
        List<PointDTO> allPoints = new ArrayList<>();
        allPoints.add(PointDTO.infinity());
        allPoints.addAll(getAllPoints(params));

        int cardinality = allPoints.size();
        List<String> scalarHeaders = new ArrayList<>();
        for (int k = 1; k <= cardinality; k++) {
            scalarHeaders.add(k + "P");
        }

        List<String> pointLabels = allPoints.stream().map(PointDTO::label).toList();
        List<List<String>> matrix = new ArrayList<>();

        for (PointDTO pt : allPoints) {
            List<String> row = new ArrayList<>();
            for (int k = 1; k <= cardinality; k++) {
                PointDTO res = multiply(params, pt, BigInteger.valueOf(k)).result();
                row.add(res.label());
            }
            matrix.add(row);
        }

        return new MultiplicationTableResponse(scalarHeaders, pointLabels, matrix);
    }
}