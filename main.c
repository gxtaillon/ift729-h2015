/*
    IFT729 - H2015
    Guillaume Xavier Taillon
    Francis Gravel Saint-Pierre
    Systeme d'authentification résistant aux attaques par force brute et déni
        de service non distribué
    
    Depend des paquets hemorraging-edge suivants (qui a leur tour ne peuvent
        tourner que sur un kernel >=3.14).
      + libnftnl0
      + libnftnl-dev
      + nftables

    Le serveur d'authentification n'a rien de bien compliqué. Il peux 
        cependant, celon le comportement d'un client modifier les regles des
        filtres reseaux a l'aide de la librairie libnftnl.
*/


        
