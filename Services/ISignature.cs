namespace sign.Services;

public interface ISignature
{
    MemoryStream Sign(MemoryStream src);
}