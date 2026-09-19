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

        // 4a^3 + 27b^2 mod p
        BigInteger term1 = a.pow(3).multiply(BigInteger.valueOf(4));
        BigInteger term2 = b.pow(2).multiply(BigInteger.valueOf(27));
        BigInteger disc = term1.add(term2).mod(p);

        if (disc.equals(BigInteger.ZERO)) {
            return new ValidationResponse(false, disc, "Curva singular: 4a³ + 27b² ≡ 0 (mod p)");
        }
        return new ValidationResponse(true, disc, "Curva elíptica no singular válida.");
    }

    public List<PointDTO> getAllPoints(CurveParams params) {
        BigInteger a = params.a();
        BigInteger b = params.b();
        BigInteger p = params.p();
        List<PointDTO> points = new ArrayList<>();

        // Evaluación exhaustiva en F_p (diseñado para p didáctico, e.g., p < 2000)
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

    public AddPointsResponse addPoints(AddPointsRequest req) {
        CurveParams c = req.curve();
        PointDTO p1 = req.p1();
        PointDTO p2 = req.p2();
        BigInteger p = c.p();

        if (p1.isInfinity())
            return new AddPointsResponse(p2, null, "IDENTITY");
        if (p2.isInfinity())
            return new AddPointsResponse(p1, null, "IDENTITY");

        // P + (-P) = O
        if (p1.x().equals(p2.x()) && !p1.y().equals(p2.y())) {
            return new AddPointsResponse(PointDTO.infinity(), null, "INVERSE_CANCEL");
        }

        BigInteger m;
        String opType;

        if (p1.x().equals(p2.x()) && p1.y().equals(p2.y())) {
            if (p1.y().equals(BigInteger.ZERO)) {
                return new AddPointsResponse(PointDTO.infinity(), null, "TANGENT_VERTICAL");
            }
            // Duplicación: m = (3*x1^2 + a) * (2*y1)^(-1) mod p
            BigInteger num = p1.x().pow(2).multiply(BigInteger.valueOf(3)).add(c.a()).mod(p);
            BigInteger den = p1.y().multiply(BigInteger.TWO).mod(p);
            m = num.multiply(den.modInverse(p)).mod(p);
            opType = "DOUBLING";
        } else {
            // Suma: m = (y2 - y1) * (x2 - x1)^(-1) mod p
            BigInteger num = p2.y().subtract(p1.y()).mod(p);
            BigInteger den = p2.x().subtract(p1.x()).mod(p);
            m = num.multiply(den.modInverse(p)).mod(p);
            opType = "ADDITION";
        }

        BigInteger x3 = m.pow(2).subtract(p1.x()).subtract(p2.x()).mod(p);
        BigInteger y3 = m.multiply(p1.x().subtract(x3)).subtract(p1.y()).mod(p);

        return new AddPointsResponse(new PointDTO(x3, y3, false), m, opType);
    }

    public MultiplyResponse multiply(MultiplyRequest req) {
        BigInteger k = req.k();
        PointDTO current = req.point();
        PointDTO result = PointDTO.infinity();
        int stepCount = 0;

        for (int i = 0; i < k.bitLength(); i++) {
            stepCount++;
            if (k.testBit(i)) {
                result = addPoints(new AddPointsRequest(req.curve(), result, current)).result();
            }
            current = addPoints(new AddPointsRequest(req.curve(), current, current)).result();
        }

        return new MultiplyResponse(result, k.bitLength(), stepCount);
    }
}