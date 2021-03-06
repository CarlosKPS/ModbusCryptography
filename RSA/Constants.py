# -*- coding: utf-8 -*-
"""
Created on Tue Feb  1 21:14:46 2022

@author: carlo
"""
# PRIME NUMBERS OF 300 DIGITS FOR TEST

PRIME1 = 413865355076791593277009873259843546571014785560352814995219549814687627386880415825118976872936684157510864218270430764748756851123243818454161045235747877293948617353611074601891655493377045178481656069220326990981369409011093767424294202041207675290414553952818622540385557626226133997130519632217
PRIME2 = 218472972539010234418007515884316764033708138720167216450533446736999281099778266187132091622535809663345527361402999627957856625194930728870903276761302680911440141830547471791447326502895240160106555777060189825551720714279424499549636696786217703044122207796045929148358628284814750079609461469299
PRIME3 = 445616471059491237272191424566888895659027444321593125458891394334229326425261531764357085720158111126414123166871511450905858514071975776565770546690190740446235838343014949333149359067401023984432305029277930913970851771580067304530938043278851247619446814940189632158350983173321179384414231228099
PRIME4 = 137716485477717210571882325599704889470458144442342302541494434581446329654535025216770338817614172299011237631246450136982373390631800752914516608427984611216774583965418209932847453510168527634541345513797792490113249368430562503563364089678237328452217742756993359500938296105136933077761299586323

EXAMPLE_E = 1752394466447128143891227677719391794465151030002303558563278635864170305468403291302527277
EXAMPLE_D = 54416382804202430530402841307839770441896983629376388739580396808419170503823987270557094444474679808034881298162939261426412846273340744656087109773266611475913648633358271727871749823641025256986123193550383296415584825665108514092721140543096369559653101934806903099079832214950341951847817230211269248458574090093336602748099381823591017481493334956656923432209673763261989117687106815629233625545365664839914226521610335662052012209197018036000109843860918171695366052946132895888409461449156578677100738724805120850786493059670648659056684029374497153608408543911459131396693712960015277016645

PLAIN_VEC =[[0, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0],
            [0, 1, 1,
             0,
             1,
             0,
             0,
             0,
             1,
             0,
             0,
             1,
             1,
             0,
             0,
             0,
             0,
             1,
             0,
             1,
             0,
             0,
             0,
             1,
             0,
             1,
             1,
             0,
             0,
             0,
             0,
             1,
             1,
             1,
             0,
             1,
             1,
             0,
             0,
             0,
             0,
             0,
             0,
             0,
             0,
             1,
             0,
             0,
             1,
             0,
             0,
             0,
             0,
             1,
             1,
             0,
             1,
             1,
             0,
             0,
             0,
             1, 0, 0],
            [0,
             0,
             1,
             1,
             1,
             0,
             1,
             1,
             0,
             0,
             0,
             0,
             1,
             0,
             0,
             0,
             1,
             0,
             1,
             0,
             1,
             1,
             0,
             1,
             1,
             0,
             1,
             1,
             0,
             0,
             0,
             0,
             1,
             1,
             1,
             1,
             0,
             0,
             0,
             1,
             1,
             1,
             1,
             1,
             1,
             1,
             1,
             0,
             1,
             1,
             0,
             0,
             1,
             1,
             1,
             0,
             0,
             0,
             0,
             1,
             0,
             1,
             1,
             0],
            [1,
             0,
             1,
             1,
             1,
             1,
             0,
             0,
             0,
             0,
             0,
             0,
             1,
             0,
             1,
             0,
             0,
             1,
             0,
             0,
             1,
             1,
             0,
             0,
             0,
             1,
             1,
             1,
             0,
             0,
             0,
             1,
             1,
             0,
             1,
             0,
             0,
             1,
             1,
             0,
             0,
             1,
             1,
             0,
             0,
             1,
             0,
             0,
             0,
             0,
             1,
             0,
             0,
             0,
             1,
             0,
             0,
             1,
             0,
             1,
             0,
             1,
             0,
             1],
            [0,
             1,
             0,
             1,
             0,
             1,
             0,
             1,
             0,
             1,
             0,
             0,
             0,
             0,
             1,
             1,
             0,
             0,
             0,
             1,
             0,
             1,
             0,
             1,
             0,
             0,
             0,
             0,
             1,
             0,
             0,
             1,
             0,
             1,
             1,
             0,
             0,
             1,
             1,
             0,
             0,
             1,
             1,
             1,
             0,
             0,
             1,
             0,
             0,
             1,
             0,
             1,
             1,
             0,
             1,
             1,
             1,
             1,
             0,
             1,
             0,
             0,
             1,
             0]]