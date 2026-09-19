package com.crypto.ec_calculator.dto;

import java.math.BigInteger;

public class ECDTOs {

    public record CurveParams(BigInteger a, BigInteger b, BigInteger p) {
    }

    public record PointDTO(BigInteger x, BigInteger y, boolean isInfinity) {
        public static PointDTO infinity() {
            return new PointDTO(null, null, true);
        }
    }

    public record ValidationResponse(
            boolean valid,
            BigInteger discriminant,
            String message) {
    }

    public record AddPointsRequest(
            CurveParams curve,
            PointDTO p1,
            PointDTO p2) {
    }

    public record AddPointsResponse(
            PointDTO result,
            BigInteger slope,
            String operationType // "ADDITION", "DOUBLING", "INFINITY"
    ) {
    }

    public record MultiplyRequest(
            CurveParams curve,
            PointDTO point,
            BigInteger k) {
    }

    public record MultiplyResponse(
            PointDTO result,
            int bitLength,
            int steps) {
    }

    public record GroupOrderResponse(
            int order,
            java.util.List<PointDTO> points) {
    }
}