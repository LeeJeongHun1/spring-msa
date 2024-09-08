package com.common.support;

import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.*;
import com.querydsl.core.types.dsl.*;
import jakarta.persistence.criteria.Expression;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public abstract class Querydsl5ExpressionSupport {

    protected OrderSpecifier<?> getSortedColumn(Order order, Path<?> parent, String fieldName) {
        Path<Object> fieldPath = Expressions.path(Object.class, parent, fieldName);
        return new OrderSpecifier(order, fieldPath);
    }


    protected <T> BooleanExpression ne(SimpleExpression<T> path, T right) {
        return Objects.nonNull(right) ? path.ne(right) : null;
    }

    protected <T> BooleanExpression eq(boolean isNull, SimpleExpression<T> path, T right) {
        if (isNull) return null;
        return Objects.nonNull(right) ? path.eq(right) : null;
    }

    protected <T> BooleanExpression eq(SimpleExpression<T> path, T right) {
        return Objects.nonNull(right) ? path.eq(right) : null;
    }

//    protected <T> BooleanExpression eq(SimpleExpression<T> path, Expression<? super T> right) {
//        return Objects.nonNull(right) ? path.eq(right) : null;
//    }

    protected <T> BooleanExpression eqUseNull(SimpleExpression<T> path, T right) {
        return Objects.nonNull(right) ? path.eq(right) : path.isNull();
    }

    protected BooleanExpression containsIgnoreCase(StringPath path, String right) {
        return Objects.nonNull(right) ? path.containsIgnoreCase(right) : null;
    }

    protected BooleanExpression contains(boolean isNull, StringPath path, String right) {
        if (isNull) return null;

        return Objects.nonNull(right) ? path.contains(right) : null;
    }

    protected BooleanExpression contains(StringPath path, String right) {
        return Objects.nonNull(right) ? path.contains(right) : null;
    }

    protected BooleanExpression contains(StringExpression path, String right) {
        return Objects.nonNull(right) ? path.contains(right) : null;
    }

    protected BooleanExpression in(EnumPath path, Set right) {
        return Objects.isNull(right) || right.isEmpty() ? null : path.in(right);
    }

    protected BooleanExpression in(NumberPath path, Set right) {
        return Objects.isNull(right) || right.isEmpty() ? null : path.in(right);
    }

    protected BooleanExpression in(StringPath path, Set right) {
        return Objects.isNull(right) || right.isEmpty() ? null : path.in(right);
    }

    protected BooleanExpression in(NumberPath path, List right) {
        return Objects.isNull(right) || right.isEmpty() ? null : path.in(right);
    }

    protected BooleanExpression in(boolean isNull, NumberPath path, List right) {
        if (isNull) return null;

        return Objects.isNull(right) || right.isEmpty() ? null : path.in(right);
    }

    protected BooleanExpression notIn(EnumPath path, Set right) {
        return Objects.isNull(right) || right.isEmpty() ? null : path.notIn(right);
    }

    protected BooleanExpression notIn(NumberPath path, Set right) {
        return Objects.isNull(right) || right.isEmpty() ? null : path.notIn(right);
    }

    protected BooleanExpression notIn(StringPath path, Set right) {
        return Objects.isNull(right) || right.isEmpty() ? null : path.notIn(right);
    }

    protected BooleanExpression notIn(NumberPath path, List right) {
        return Objects.isNull(right) || right.isEmpty() ? null : path.notIn(right);
    }

    protected BooleanExpression notIn(boolean isNull, NumberPath path, List right) {
        if (isNull) return null;

        return Objects.isNull(right) || right.isEmpty() ? null : path.notIn(right);
    }

    protected BooleanExpression lt(NumberPath path, Long id) {
        return Objects.nonNull(id) ? path.lt(id) : null;
    }

    protected BooleanExpression loe(NumberPath path, Long id) {
        return Objects.nonNull(id) ? path.loe(id) : null;
    }

    protected BooleanExpression gt(NumberPath path, Long id) {
        return Objects.nonNull(id) ? path.gt(id) : null;
    }

    protected BooleanExpression goe(NumberPath path, Long id) {
        return Objects.nonNull(id) ? path.goe(id) : null;
    }

    protected <D extends Comparable> DateTimeExpression<D> addMinutes(DateTimeExpression<D> date, Long minutes) {
        return Expressions.dateTimeOperation(date.getType(), Ops.DateTimeOps.ADD_MINUTES, date, ConstantImpl.create(minutes));
    }

    protected BooleanExpression between(DateTimePath<LocalDateTime> path, LocalDateTime from, LocalDateTime to) {
//        from = convertToUtc(from);
//        to = convertToUtc(to);

        if (Objects.isNull(from) && Objects.isNull(to)) return null;
        else if (Objects.isNull(to)) return path.goe(from);
        else if (Objects.isNull(from)) return path.loe(to);
        else return path.between(from, to);
    }

    protected BooleanExpression between(DateTimePath<LocalDateTime> path, LocalDate from, LocalDate to) {
        return between(path, ld2ldtFromDate(from), ld2ldtToDate(to));
    }

    protected BooleanExpression between(DateTimePath<LocalDateTime> path, LocalDate targetDate) {
        return between(path, ld2ldtFromDate(targetDate), ld2ldtToDate(targetDate));
    }

    protected BooleanExpression between(DatePath<LocalDate> path, LocalDate from, LocalDate to) {
        if (Objects.isNull(from) && Objects.isNull(to)) return null;
        else if (Objects.isNull(to)) return path.goe(from);
        else if (Objects.isNull(from)) return path.loe(to);
        else return path.between(from, to);
    }


    protected BooleanBuilder between(LocalDate target, DatePath<LocalDate> fromPath, DatePath<LocalDate> toPath) {
        if (Objects.isNull(target)) return null;

        BooleanBuilder builder = new BooleanBuilder();
        builder.and(fromPath.loe(target));
        builder.and(toPath.goe(target));

        return builder;
    }

    protected LocalDateTime ld2ldtFromDate(LocalDate fromDate) {
        if (Objects.nonNull(fromDate)) return fromDate.atTime(0, 0, 0);
        else return null;
    }

    protected LocalDateTime ld2ldtToDate(LocalDate toDate) {
        if (Objects.nonNull(toDate)) return toDate.atTime(23, 59, 59);
        else return null;
    }

    private LocalDateTime convertToUtc(LocalDateTime localDateTime) {
        if (Objects.nonNull(localDateTime))
            return localDateTime.atZone(ZoneId.systemDefault()).withZoneSameInstant(ZoneId.of("UTC")).toLocalDateTime();
        else return null;
    }

}