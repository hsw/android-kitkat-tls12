.class public Lcom/vendor/Caller;
.super Ljava/lang/Object;
.source "Caller.java"


# direct methods
.method public static call()I
    .registers 1

    .prologue
    .line 2
    invoke-static {}, Lcom/example/Gone;->value()I

    move-result v0

    return v0
.end method
