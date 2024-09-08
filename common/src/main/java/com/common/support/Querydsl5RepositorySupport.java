package com.common.support;

import com.querydsl.core.types.EntityPath;
import com.querydsl.core.types.Expression;
import com.querydsl.core.types.Order;
import com.querydsl.core.types.OrderSpecifier;
import com.querydsl.core.types.dsl.PathBuilder;
import com.querydsl.jpa.JPQLTemplates;
import com.querydsl.jpa.impl.JPADeleteClause;
import com.querydsl.jpa.impl.JPAQuery;
import com.querydsl.jpa.impl.JPAQueryFactory;
import com.querydsl.jpa.impl.JPAUpdateClause;
import jakarta.annotation.PostConstruct;
import jakarta.persistence.EntityManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.support.JpaEntityInformation;
import org.springframework.data.jpa.repository.support.JpaEntityInformationSupport;
import org.springframework.data.jpa.repository.support.Querydsl;
import org.springframework.data.querydsl.SimpleEntityPathResolver;
import org.springframework.data.support.PageableExecutionUtils;
import org.springframework.stereotype.Repository;
import org.springframework.util.Assert;

import java.util.List;
import java.util.function.Function;

// Querydsl 4.x 버전에 맞춘 Querydsl 지원 라이브러리
@Repository
public abstract class Querydsl5RepositorySupport extends Querydsl5ExpressionSupport {
    private final Class<?> domainClass;
    private Querydsl querydsl;
    private EntityManager entityManager;
    private JPAQueryFactory queryFactory;

    protected Querydsl5RepositorySupport(Class<?> domainClass) {
        Assert.notNull(domainClass, "Domain class must not be null!");
        this.domainClass = domainClass;
    }

    @Autowired
    public void setEntityManager(EntityManager entityManager) {
        Assert.notNull(entityManager, "EntityManager must not be null!");
        JpaEntityInformation<?, ?> entityInformation = JpaEntityInformationSupport.getEntityInformation(domainClass, entityManager);
        SimpleEntityPathResolver resolver = SimpleEntityPathResolver.INSTANCE;
        EntityPath<?> path = resolver.createPath(entityInformation.getJavaType());
        this.entityManager = entityManager;
        this.querydsl = new Querydsl(entityManager, new PathBuilder<>(path.getType(), path.getMetadata()));
        this.queryFactory = new JPAQueryFactory(JPQLTemplates.DEFAULT, entityManager);
    }

    @PostConstruct
    public void validate() {
        Assert.notNull(entityManager, "EntityManager must not be null.");
        Assert.notNull(querydsl, "Querydsl must not be null.");
        Assert.notNull(queryFactory, "QueryFactory must not be null.");
    }

    protected JPAQueryFactory getQueryFactory() {
        return queryFactory;
    }

    protected Querydsl getQuerydsl() {
        return querydsl;
    }

    protected EntityManager getEntityManager() {
        return entityManager;
    }

    protected <T> JPAQuery<T> select(Expression<T> expr) {
        return getQueryFactory().select(expr);
    }

    protected <T> JPAQuery<T> selectFrom(EntityPath<T> from) {
        return getQueryFactory().selectFrom(from);
    }

    protected <T> Page<T> applyPagination(Pageable pageable,
                                          Function<JPAQueryFactory, JPAQuery<T>> contentQuery) {
        JPAQuery<T> jpaContentQuery = contentQuery.apply(getQueryFactory());
        long totalCount = jpaContentQuery.fetch().size();
        List<T> content = getQuerydsl().applyPagination(pageable, jpaContentQuery).fetch();
        return PageableExecutionUtils.getPage(content, pageable, () -> totalCount);
    }

    protected <T> Page<T> applyPagination(JPAQuery<T> query, Pageable pageable) {
        int totalCount = query.fetch().size();
        query.offset(pageable.getOffset()).limit(pageable.getPageSize());
        return PageableExecutionUtils.getPage(query.fetch(), pageable, () -> totalCount);
    }

    protected JPAUpdateClause update(EntityPath<?> path) {
        return getQueryFactory().update(path);
    }
    protected JPADeleteClause delete(EntityPath<?> path) {
        return getQueryFactory().delete(path);
    }

    protected OrderSpecifier<?>[] getOrderSpecifier(Class<?> clazz, Sort sort, String tableAlias) {
        return sort.stream().map(order -> {
            PathBuilder<Object> pathBuilder = new PathBuilder<>(clazz, tableAlias);
            PathBuilder<Object> field = pathBuilder.get(order.getProperty());

            Order direction = order.isAscending() ? Order.ASC : Order.DESC;
            return new OrderSpecifier(direction, field).nullsLast();

        }).toArray(OrderSpecifier[]::new);
    }

}