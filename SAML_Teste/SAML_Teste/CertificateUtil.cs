using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates; 
 
/// <summary> 
/// A utility class which helps to retrieve an x509 certificate 
/// </summary> 
public class CertificateUtil 
{ 
    /// <summary> 
    /// Get the certificate from a specific store/location/subject. 
    /// </summary> 
    public static X509Certificate2 GetCertificate( StoreName name, StoreLocation location, string subjectName ) 
    { 
        X509Store store = new X509Store( name, location ); 
        X509Certificate2Collection certificates = null; 
        store.Open( OpenFlags.ReadOnly );
        List<string> aux;

 
        try 
        { 
            X509Certificate2 result = null; 
 
            // 
            // Every time we call store.Certificates property, a new collection will be returned. 
            // 
            certificates = store.Certificates; 
 
            for ( int i = 0; i < certificates.Count; i++ ) 
            {
                if (result == null) { 
                    X509Certificate2 cert = certificates[i];

                    aux = Parse(cert.SubjectName.Name.ToString(), "=");
                    if (aux[0].ToString().ToLower() == subjectName.ToLower())
                    {
                        if (result != null)
                        {
                            throw new ApplicationException(string.Format("More than one certificate was found for subject Name {0}", subjectName));
                        }
                        result = new X509Certificate2(cert);
                    }
                }
            } 
 
            if ( result == null ) 
            { 
                throw new ApplicationException( string.Format( "No certificate was found for subject Name {0}", subjectName ) ); 
            } 
 
            return result; 
        } 
        finally 
        { 
            if ( certificates != null ) 
            { 
                for ( int i = 0; i < certificates.Count; i++ ) 
                { 
                    X509Certificate2 cert = certificates[i]; 
                    cert.Reset(); 
                } 
            } 
 
            store.Close(); 
        } 
    }

    public static List<string> Parse(string data, string delimiter)
    {
        if (data == null) return null;

        if (!delimiter.EndsWith("=")) delimiter = delimiter + "=";

        //data = data.ToUpper(); // why did i add this?
        if (!data.Contains(delimiter)) return null;

        //base case
        var result = new List<string>();
        int start = data.IndexOf(delimiter) + 1; //+3
        int length = data.IndexOf(',', start) - start;
        if (length == 0) return null; //the group is empty
        if (length > 0)
        {
            result.Add(data.Substring(start, length));

            var rec = Parse(data.Substring(start + length), delimiter);
            if (rec != null) result.AddRange(rec); //can't pass null into AddRange() :(
        }
        else //no comma found after current group so just use the whole remaining string
        {
            result.Add(data.Substring(start));
        }

        return result;
    }
} 
 