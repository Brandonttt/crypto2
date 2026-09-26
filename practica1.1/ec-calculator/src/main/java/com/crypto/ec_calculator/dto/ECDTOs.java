package com.crypto.ec_calculator.dto;

import java.math.BigInteger;
import java.util.List;

public class ECDTOs {

    public record CurveParams(BigInteger a, BigInteger b, BigInteger p) {}

    public record PointDTO(BigInteger x, BigInteger y, boolean isInfinity) {
        public static PointDTO infinity() {
            return new PointDTO(null, null, true);
        }

        public String label() {
            return isInfinity ? "𝒪" : "(" + x + ", " + y + ")";
        }
    }

    public record ValidationResponse(
            boolean valid,
            BigInteger discriminant,
            String message
    ) {}

    public record AnalysisResponse(
            int cardinality,
            List<PointDTO> points,
            List<PointDTO> generators
    ) {}

    public record OperationRequest(
            CurveParams curve,
            PointDTO p1,
            PointDTO p2
    ) {}

    public record OperationResponse(
            PointDTO result,
            BigInteger slope,
            String operationType
    ) {}

    public record ScalarMultiplyRequest(
            CurveParams curve,
            PointDTO point,
            BigInteger k
    ) {}

    public record ScalarMultiplyResponse(
            PointDTO result,
            int steps,
            int bitLength
    ) {}

    public record AdditionTableResponse(
            List<String> headers,
            List<List<String>> matrix
    ) {}

    public record MultiplicationTableResponse(
            List<String> scalarHeaders,
            List<String> pointLabels,
            List<List<String>> matrix
    ) {}
}